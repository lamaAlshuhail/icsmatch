"""exploitation signals and the prioritisation decision.

CVSS measures severity in isolation and says nothing about whether anyone is
exploiting the issue or whether the asset is reachable. three signals are
combined instead:

    exploitation  CISA KEV membership, then EPSS as a likelihood proxy
    exposure      the Purdue level of the asset
    impact        severity, escalated where the asset drives the process

the decision is a small tree in the shape of the SSVC deployer tree, and it
emits a vector so the branch that fired is visible. it is
a customised tree, not a verbatim reproduction of CISA's.
"""

from __future__ import annotations

import contextlib
import csv
import gzip
import io
import json
import urllib.request
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

__all__ = [
    "Priority",
    "Enrichment",
    "Decision",
    "load_kev",
    "load_epss",
    "prioritise",
    "KEV_URL",
    "EPSS_URL",
    "EPSS_ACTIVE",
]

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

# FIRST is explicit that no universal EPSS threshold exists. this is the
# working cutoff, exposed so it can be tuned per site.
EPSS_ACTIVE = 0.10


class Priority(str, Enum):
    NOW = "NOW"
    NEXT = "NEXT"
    TRACK = "TRACK"
    LATER = "LATER"


_PRIORITY_ORDER = {Priority.NOW: 0, Priority.NEXT: 1, Priority.TRACK: 2, Priority.LATER: 3}


def priority_rank(p: Priority) -> int:
    return _PRIORITY_ORDER[p]


@dataclass
class Enrichment:
    kev: set[str]
    epss: dict[str, float]

    def is_kev(self, cve: str) -> bool:
        return cve in self.kev

    def epss_of(self, cve: str) -> float:
        return self.epss.get(cve, 0.0)

    def max_epss(self, cves: list[str]) -> float:
        return max((self.epss_of(c) for c in cves), default=0.0)

    def any_kev(self, cves: list[str]) -> bool:
        return any(self.is_kev(c) for c in cves)


def load_kev(cache: Path | str | None = None, *, offline: bool = False) -> set[str]:
    """CISA known exploited vulnerabilities, cached to disk for offline runs."""
    cache = Path(cache) if cache else Path.home() / ".cache" / "icsmatch" / "kev.json"
    if not offline:
        try:
            cache.parent.mkdir(parents=True, exist_ok=True)
            with urllib.request.urlopen(KEV_URL, timeout=30) as resp:
                cache.write_bytes(resp.read())
        except Exception:
            pass

    if not cache.exists():
        return set()
    try:
        data = json.loads(cache.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    return {v.get("cveID", "") for v in data.get("vulnerabilities", []) if v.get("cveID")}


def load_epss(cache: Path | str | None = None, *, offline: bool = False) -> dict[str, float]:
    """current EPSS scores, cve -> probability."""
    cache = Path(cache) if cache else Path.home() / ".cache" / "icsmatch" / "epss.csv"
    if not offline:
        try:
            cache.parent.mkdir(parents=True, exist_ok=True)
            with urllib.request.urlopen(EPSS_URL, timeout=60) as resp:
                raw = gzip.decompress(resp.read())
            cache.write_bytes(raw)
        except Exception:
            pass

    if not cache.exists():
        return {}
    scores: dict[str, float] = {}
    try:
        with cache.open(encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("#"):
                    continue
                for row in csv.reader(io.StringIO(line)):
                    if len(row) >= 2 and row[0].startswith("CVE-"):
                        with contextlib.suppress(ValueError):
                            scores[row[0]] = float(row[1])
    except OSError:
        return {}
    return scores


# purdue levels 3 and above sit closer to the enterprise network and are
# reachable from a typical initial-access foothold.
_OPEN_LEVELS = {"3.5", "4", "5", "dmz"}
_CONTROLLED_LEVELS = {"2", "3"}
_PROCESS_LEVELS = {"0", "1"}


def _exposure(purdue_level: str) -> str:
    lvl = purdue_level.strip().lower()
    if lvl in _OPEN_LEVELS:
        return "open"
    if lvl in _CONTROLLED_LEVELS:
        return "controlled"
    if lvl in _PROCESS_LEVELS:
        return "small"
    return "controlled"


def _exploitation(cves: list[str], enrichment: Enrichment, epss_cutoff: float) -> tuple[str, str]:
    if enrichment.any_kev(cves):
        hits = [c for c in cves if enrichment.is_kev(c)]
        return "active", f"in CISA KEV ({', '.join(hits[:3])})"
    epss = enrichment.max_epss(cves)
    if epss >= epss_cutoff:
        return "poc", f"EPSS {epss:.1%}"
    return "none", "no exploitation signal"


def _automatable(cvss_vector: str) -> bool:
    """true when the vector says the bug is reachable without a human.

    reads CVSS v4 AU:Y directly, and infers it for v3 from a network vector
    that needs no privileges and no user interaction.
    """
    v = (cvss_vector or "").upper()
    if "AU:Y" in v:
        return True
    if "AU:N" in v and "CVSS:4" in v:
        return False
    if "CVSS:3" in v:
        return "AV:N" in v and "PR:N" in v and "UI:N" in v
    return False


def _safety_flag(cvss_vector: str) -> bool:
    v = (cvss_vector or "").upper()
    if "CVSS:4" not in v:
        return False
    parts = set(v.split("/"))
    return bool(parts & {"S:P", "MSI:S", "MSA:S"})


def _impact(cvss: float | None, purdue_level: str, cvss_vector: str) -> str:
    score = cvss or 0.0
    if score >= 9.0:
        level = "very high"
    elif score >= 7.0:
        level = "high"
    elif score >= 4.0:
        level = "medium"
    else:
        level = "low"

    # safety consequence concentrates at the levels that touch the process.
    # CVSS 4.0 carries safety as the supplemental S:P or the environmental
    # MSI:S / MSA:S. SC is subsequent-system confidentiality, not safety.
    safety = _safety_flag(cvss_vector)
    if purdue_level.strip().lower() in _PROCESS_LEVELS and (score >= 7.0 or safety):
        order = ["low", "medium", "high", "very high"]
        level = order[min(order.index(level) + 1, 3)]
    return level


_ACTION = {
    "immediate": Priority.NOW,
    "out-of-cycle": Priority.NEXT,
    "scheduled": Priority.NEXT,
    "defer": Priority.LATER,
}

_CODE = {
    "none": "N", "poc": "P", "active": "A",
    "small": "S", "controlled": "C", "open": "O",
    "laborious": "L", "efficient": "E",
    "low": "L", "medium": "M", "high": "H", "very high": "V",
    "defer": "D", "scheduled": "S", "out-of-cycle": "O", "immediate": "I",
}


def _decide(exploitation: str, exposure: str, utility: str, impact: str) -> str:
    """the deployer tree, collapsed to the branches that matter here."""
    if exploitation == "active":
        # confirmed exploitation in the wild. only a low-impact issue on an
        # asset with no reachable path waits for the next window.
        if impact == "low" and exposure == "small":
            return "out-of-cycle"
        return "immediate"

    if exploitation == "poc":
        if exposure == "open" and impact in ("high", "very high"):
            return "immediate"
        if impact in ("high", "very high") or utility == "efficient":
            return "out-of-cycle"
        return "scheduled"

    if impact == "very high" and exposure in ("open", "controlled"):
        return "out-of-cycle"
    if impact in ("high", "very high"):
        return "scheduled"
    if impact == "medium" and exposure == "open":
        return "scheduled"
    return "defer"


@dataclass(frozen=True)
class Decision:
    priority: Priority
    action: str
    exploitation: str
    exposure: str
    utility: str
    impact: str
    rationale: str

    @property
    def vector(self) -> str:
        return (
            f"SSVCv2/E:{_CODE[self.exploitation]}"
            f"/X:{_CODE[self.exposure]}"
            f"/U:{_CODE[self.utility]}"
            f"/H:{_CODE[self.impact]}"
            f"/D:{_CODE[self.action]}"
        )


def prioritise(
    *,
    cves: list[str],
    cvss: float | None,
    enrichment: Enrichment,
    has_patch: bool,
    purdue_level: str = "",
    cvss_vector: str = "",
    epss_cutoff: float = EPSS_ACTIVE,
) -> tuple[Priority, str]:
    """return (priority, rationale). the rationale goes straight into reports."""
    d = decide(
        cves=cves,
        cvss=cvss,
        enrichment=enrichment,
        has_patch=has_patch,
        purdue_level=purdue_level,
        cvss_vector=cvss_vector,
        epss_cutoff=epss_cutoff,
    )
    return d.priority, d.rationale


def decide(
    *,
    cves: list[str],
    cvss: float | None,
    enrichment: Enrichment,
    has_patch: bool,
    purdue_level: str = "",
    cvss_vector: str = "",
    epss_cutoff: float = EPSS_ACTIVE,
) -> Decision:
    """full decision with the decision points that produced it."""
    exploitation, exploit_why = _exploitation(cves, enrichment, epss_cutoff)
    exposure = _exposure(purdue_level)
    utility = "efficient" if _automatable(cvss_vector) else "laborious"
    impact = _impact(cvss, purdue_level, cvss_vector)

    action = _decide(exploitation, exposure, utility, impact)
    priority = _ACTION[action]

    # an issue with no vendor fix cannot be scheduled into a patch window. it
    # needs a compensating control, which is a different queue.
    if priority is not Priority.NOW and not has_patch:
        priority = Priority.TRACK

    score = f"CVSS {cvss:.1f}" if cvss is not None else "no CVSS"
    parts = [exploit_why, f"{score}", f"{exposure} exposure"]
    if purdue_level:
        parts[-1] = f"{exposure} exposure at Purdue level {purdue_level}"
    if priority is Priority.TRACK:
        parts.append("no vendor patch, compensating controls only")
    rationale = ", ".join(parts)

    return Decision(
        priority=priority,
        action=action,
        exploitation=exploitation,
        exposure=exposure,
        utility=utility,
        impact=impact,
        rationale=rationale,
    )
