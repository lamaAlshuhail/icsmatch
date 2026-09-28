"""report rendering.

findings are ordered NOW, NEXT, TRACK, LATER. every row carries its basis
string so the reasoning is auditable without this tool.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone

from ..ingest.enrich import Decision, Enrichment, Priority, decide, priority_rank
from ..match.engine import Match, Verdict

__all__ = ["ScoredMatch", "score_matches", "render_markdown", "render_json"]


@dataclass
class ScoredMatch:
    match: Match
    decision: Decision
    epss: float
    kev: bool

    @property
    def priority(self) -> Priority:
        return self.decision.priority

    @property
    def rationale(self) -> str:
        return self.decision.rationale

    @property
    def cves(self) -> list[str]:
        return self.match.cves


def score_matches(matches: list[Match], enrichment: Enrichment) -> list[ScoredMatch]:
    out: list[ScoredMatch] = []
    for m in matches:
        cves = m.cves
        out.append(
            ScoredMatch(
                match=m,
                decision=decide(
                    cves=cves,
                    cvss=m.cvss,
                    enrichment=enrichment,
                    has_patch=m.advisory.has_patch,
                    purdue_level=m.asset.purdue_level,
                    cvss_vector=m.cvss_vector,
                ),
                epss=enrichment.max_epss(cves),
                kev=enrichment.any_kev(cves),
            )
        )
    out.sort(
        key=lambda s: (priority_rank(s.priority), s.match.tier, -(s.match.cvss or 0.0))
    )
    return out


_VERDICT_ICON = {
    Verdict.AFFECTED: "affected",
    Verdict.REVIEW: "review",
    Verdict.MANUAL: "skim",
    Verdict.UNKNOWN: "unconfirmed",
    Verdict.NOT_AFFECTED: "not affected",
}


def render_markdown(
    scored: list[ScoredMatch],
    *,
    client: str = "Inventory",
    total_assets: int = 0,
    total_advisories: int = 0,
) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines: list[str] = []

    counts = {p: sum(1 for s in scored if s.priority is p) for p in Priority}
    affected_assets = len({s.match.asset.asset_id for s in scored})

    lines += [
        f"# ICS Advisory Triage: {client}",
        "",
        f"*Generated {now} with `icsmatch`*",
        "",
        "## Summary",
        "",
        "| | |",
        "|---|---|",
        f"| Assets in scope | {total_assets} |",
        f"| Advisories screened | {total_advisories:,} |",
        f"| Assets with findings | {affected_assets} |",
        f"| **Act now** | **{counts[Priority.NOW]}** |",
        f"| Next patch window | {counts[Priority.NEXT]} |",
        f"| Track, no patch | {counts[Priority.TRACK]} |",
        f"| Later | {counts[Priority.LATER]} |",
        "",
    ]

    if not scored:
        lines += ["No advisories matched the supplied inventory.", ""]
        return "\n".join(lines)

    for prio in Priority:
        group = [s for s in scored if s.priority is prio]
        if not group:
            continue
        lines += [f"## {prio.value}", "", _table(group), ""]

    lines += [
        "## How to read this",
        "",
        "Every finding states how it was matched:",
        "",
        "| Tier | Basis | Confidence | Action |",
        "|---|---|---|---|",
        "| 0 | Analyst-confirmed alias | 1.00 | Treat as confirmed |",
        "| 1 | Model or SKU exact match | 1.00 | Treat as confirmed |",
        "| 2 | CPE exact match | 0.95 | Treat as confirmed |",
        "| 3 | Vendor, product and version in range | 0.85 | Treat as confirmed |",
        "| 4 | Fuzzy product match | ~0.50 | **Verify before acting** |",
        "| 5 | Vendor only | 0.30 | Skim bucket |",
        "",
        "Priority is not CVSS order. Confirmed exploitation outranks raw "
        "severity, and issues with no vendor fix are separated into TRACK "
        "because they need compensating controls rather than a patch window. "
        "The SSVC vector on each row records the decision points used.",
        "",
    ]
    return "\n".join(lines)


def _table(group: list[ScoredMatch]) -> str:
    rows = [
        "| Asset | Site | Advisory | CVSS | EPSS | KEV | Tier | SSVC | Why |",
        "|---|---|---|---|---|:--:|:--:|---|---|",
    ]
    for s in group:
        m = s.match
        cvss = f"{m.cvss:.1f}" if m.cvss is not None else "n/a"
        epss = f"{s.epss:.1%}" if s.epss else "n/a"
        kev = "yes" if s.kev else ""
        basis = m.basis.replace("|", "\\|")
        rows.append(
            f"| `{m.asset.asset_id}` | {m.asset.site or 'n/a'} "
            f"| [{m.advisory.advisory_id}]"
            f"(https://www.cisa.gov/news-events/ics-advisories/{m.advisory.base_id.lower()}) "
            f"| {cvss} | {epss} | {kev} | T{int(m.tier)} "
            f"| `{s.decision.vector}` | {basis} |"
        )
    return "\n".join(rows)


def render_json(scored: list[ScoredMatch]) -> str:
    """machine-readable output for downstream ingest."""
    payload = [
        {
            "asset_id": s.match.asset.asset_id,
            "site": s.match.asset.site,
            "purdue_level": s.match.asset.purdue_level,
            "advisory_id": s.match.advisory.advisory_id,
            "advisory_title": s.match.advisory.title,
            "tlp": s.match.advisory.tlp,
            "cves": s.cves,
            "cvss": s.match.cvss,
            "cvss_vector": s.match.cvss_vector,
            "epss": s.epss,
            "in_kev": s.kev,
            "priority": s.priority.value,
            "ssvc_vector": s.decision.vector,
            "ssvc_action": s.decision.action,
            "rationale": s.rationale,
            "match_tier": int(s.match.tier),
            "confidence": s.match.confidence,
            "verdict": s.match.verdict.value,
            "match_basis": s.match.basis,
            "vendor": s.match.product.vendor,
            "product": s.match.product.product_name,
            "version_range": s.match.product.version_range.raw,
        }
        for s in scored
    ]
    return json.dumps(payload, indent=2)
