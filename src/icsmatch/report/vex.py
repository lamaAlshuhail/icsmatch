"""OpenVEX 0.2.0 export.

each verdict becomes a statement carrying its status, justification and the
basis string that produced it.

status mapping follows the OpenVEX vocabulary:

    AFFECTED                      -> affected
    NOT_AFFECTED                  -> not_affected  (justification required)
    REVIEW, MANUAL, UNKNOWN       -> under_investigation
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from ..match.engine import Match, Verdict

__all__ = ["VEX_CONTEXT", "Justification", "render_vex"]

VEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"


class Justification:
    """the five not_affected justifications OpenVEX allows."""

    COMPONENT_NOT_PRESENT = "component_not_present"
    VULNERABLE_CODE_NOT_PRESENT = "vulnerable_code_not_present"
    VULNERABLE_CODE_NOT_IN_EXECUTE_PATH = "vulnerable_code_not_in_execute_path"
    VULNERABLE_CODE_CANNOT_BE_CONTROLLED = (
        "vulnerable_code_cannot_be_controlled_by_adversary"
    )
    INLINE_MITIGATIONS_ALREADY_EXIST = "inline_mitigations_already_exist"


_STATUS = {
    Verdict.AFFECTED: "affected",
    Verdict.NOT_AFFECTED: "not_affected",
    Verdict.REVIEW: "under_investigation",
    Verdict.MANUAL: "under_investigation",
    Verdict.UNKNOWN: "under_investigation",
}


def _purl(vendor: str, product: str, version: str) -> str:
    """a generic purl for an OT device.

    OT assets have no package ecosystem, so pkg:generic is the closest fit.
    """

    def seg(text: str) -> str:
        return "".join(c if c.isalnum() or c in "._-" else "-" for c in text.strip().lower())

    base = f"pkg:generic/{seg(vendor) or 'unknown'}/{seg(product) or 'unknown'}"
    return f"{base}@{seg(version)}" if version else base


def _product_block(m: Match) -> dict[str, object]:
    a = m.asset
    ids: dict[str, str] = {"purl": _purl(a.vendor, a.product, a.version)}
    block: dict[str, object] = {
        "@id": f"urn:icsmatch:asset:{a.asset_id}",
        "identifiers": ids,
    }
    if a.model:
        ids["model_number"] = a.model
    return block


def render_vex(
    matches: list[Match],
    *,
    author: str = "icsmatch",
    doc_id: str = "",
    version: int = 1,
    now: datetime | None = None,
) -> str:
    """render matches as an OpenVEX document.

    one statement per (CVE, status, justification) group, so a CVE that hits
    six assets the same way produces one statement listing six products
    rather than six near-identical statements.
    """
    stamp = (now or datetime.now(timezone.utc)).replace(microsecond=0).isoformat()

    groups: dict[tuple[str, str, str], list[Match]] = {}
    for m in matches:
        status = _STATUS.get(m.verdict)
        if status is None:
            continue
        just = _justification(m) if status == "not_affected" else ""
        for cve in m.cves:
            if not cve:
                continue
            groups.setdefault((cve, status, just), []).append(m)

    statements: list[dict[str, object]] = []
    for (cve, status, just), hits in sorted(groups.items()):
        seen: dict[str, dict[str, object]] = {}
        for m in hits:
            block = _product_block(m)
            seen[str(block["@id"])] = block
        stmt: dict[str, object] = {
            "vulnerability": {"name": cve},
            "products": list(seen.values()),
            "status": status,
        }
        if just:
            stmt["justification"] = just
        stmt["impact_statement" if status == "not_affected" else "status_notes"] = (
            _notes(hits)
        )
        statements.append(stmt)

    body: dict[str, object] = {
        "@context": VEX_CONTEXT,
        "author": author,
        "timestamp": stamp,
        "version": version,
        "tooling": "icsmatch",
        "statements": statements,
    }
    body["@id"] = doc_id or _doc_id(body)
    ordered = {k: body[k] for k in ("@context", "@id", "author", "timestamp", "version", "tooling", "statements")}
    return json.dumps(ordered, indent=2, sort_keys=False) + "\n"


def _doc_id(body: dict[str, object]) -> str:
    digest = hashlib.sha256(
        json.dumps(body.get("statements"), sort_keys=True).encode()
    ).hexdigest()[:16]
    return f"https://openvex.dev/docs/icsmatch/vex-{digest}"


def _justification(m: Match) -> str:
    """why a product is not affected.

    an advisory that names the product under known_not_affected is the vendor
    saying the vulnerable code is not present. an analyst rejection is the
    operator saying the product is not the one in the advisory.
    """
    if m.basis.startswith("analyst rejected"):
        return Justification.COMPONENT_NOT_PRESENT
    return Justification.VULNERABLE_CODE_NOT_PRESENT


def _notes(hits: list[Match]) -> str:
    bases = sorted({h.basis for h in hits})
    advisories = sorted({h.advisory.advisory_id for h in hits})
    lead = ", ".join(advisories[:3])
    if len(advisories) > 3:
        lead += f" and {len(advisories) - 3} more"
    return f"{lead}: {bases[0]}"
