"""portfolio view across several inventories.

each inventory keeps its own report file. the portfolio summary carries counts
and public advisory identifiers only, never asset identifiers from another
inventory.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from ..ingest.enrich import Priority
from ..report.markdown import ScoredMatch

__all__ = ["ClientResult", "render_portfolio"]


@dataclass
class ClientResult:
    name: str
    asset_count: int
    scored: list[ScoredMatch] = field(default_factory=list)
    report_path: str = ""

    @property
    def counts(self) -> dict[Priority, int]:
        return {p: sum(1 for s in self.scored if s.priority is p) for p in Priority}

    @property
    def now(self) -> int:
        return self.counts[Priority.NOW]

    @property
    def affected_assets(self) -> int:
        return len({s.match.asset.asset_id for s in self.scored})


def render_portfolio(results: list[ClientResult], *, org: str = "") -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    ordered = sorted(results, key=lambda r: (-r.now, -r.counts[Priority.NEXT], r.name))

    total_now = sum(r.now for r in ordered)
    total_assets = sum(r.asset_count for r in ordered)
    with_now = sum(1 for r in ordered if r.now)

    lines = [
        f"# Portfolio Advisory Triage: {org}" if org else "# Portfolio Advisory Triage",
        "",
        f"*Generated {now} with `icsmatch`*",
        "",
        "## Summary",
        "",
        "| | |",
        "|---|---|",
        f"| Inventories screened | {len(ordered)} |",
        f"| Assets in scope | {total_assets:,} |",
        f"| **Inventories needing immediate action** | **{with_now}** |",
        f"| **Total NOW findings** | **{total_now}** |",
        "",
        "## By inventory",
        "",
        "| Inventory | Assets | Affected | NOW | NEXT | TRACK | LATER | Report |",
        "|---|---:|---:|---:|---:|---:|---:|---|",
    ]

    for r in ordered:
        c = r.counts
        link = f"[{r.name}]({r.report_path})" if r.report_path else r.name
        lines.append(
            f"| {link} | {r.asset_count} | {r.affected_assets} "
            f"| **{c[Priority.NOW]}** | {c[Priority.NEXT]} "
            f"| {c[Priority.TRACK]} | {c[Priority.LATER]} "
            f"| {r.report_path or 'n/a'} |"
        )

    lines += ["", "## Shared exposure", ""]
    lines.append(_shared_table(ordered))
    lines += [
        "",
        "---",
        "",
        "Asset identifiers are not shared across reports. This summary carries "
        "counts and public advisory identifiers only.",
        "",
    ]
    return "\n".join(lines)


@dataclass
class _SharedAdvisory:
    advisory_id: str
    title: str
    clients: set[str] = field(default_factory=set)
    cvss: float = 0.0
    kev: bool = False


def _shared_table(results: list[ClientResult]) -> str:
    """advisories hitting more than one inventory."""
    by_advisory: dict[str, _SharedAdvisory] = {}
    for r in results:
        for s in r.scored:
            if s.priority not in (Priority.NOW, Priority.NEXT):
                continue
            adv = s.match.advisory
            entry = by_advisory.setdefault(
                adv.advisory_id,
                _SharedAdvisory(advisory_id=adv.advisory_id, title=adv.title),
            )
            entry.clients.add(r.name)
            entry.kev = entry.kev or s.kev
            entry.cvss = max(entry.cvss, s.match.cvss or 0.0)

    shared = [e for e in by_advisory.values() if len(e.clients) > 1]
    if not shared:
        return "_No advisory affects more than one inventory at NOW or NEXT priority._"

    rows = [
        "| Advisory | Inventories | CVSS | KEV | Title |",
        "|---|---:|---:|:--:|---|",
    ]
    for e in sorted(shared, key=lambda x: (-len(x.clients), -x.cvss))[:25]:
        rows.append(
            f"| [{e.advisory_id}]"
            f"(https://www.cisa.gov/news-events/ics-advisories/{e.advisory_id.split('~', 1)[0].lower()}) "
            f"| {len(e.clients)} | {e.cvss:.1f} "
            f"| {'yes' if e.kev else ''} | {e.title[:56]} |"
        )
    return "\n".join(rows)
