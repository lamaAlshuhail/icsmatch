"""CSAF 2.0 advisory ingest.

CISA publishes every ICS advisory as CSAF 2.0 JSON at
https://github.com/cisagov/CSAF, back to 2010. we consume that directly
rather than scraping HTML.

the structural thing to know: product_tree and vulnerabilities are separate
top-level blocks joined by product_id. the tree is an arbitrarily nested set
of branches where each level has a category (vendor / product_family /
product_name / product_version / product_version_range) and the leaf carries
the product object holding the product_id. flattening that into
(vendor, product, version) triples is most of the work.

product_status is honoured rather than ignored. CSAF defines eight arrays and
only known_affected, first_affected and last_affected justify a finding.
known_not_affected and fixed are the vendor telling you to stop looking.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from ..normalize.product import ProductKey, canon_vendor, product_key
from ..normalize.versions import RangeKind, VersionRange, parse_range

__all__ = [
    "CSAFProduct",
    "CSAFVuln",
    "Advisory",
    "ProductStatus",
    "parse_advisory",
    "iter_advisory_files",
]


class ProductStatus(str, Enum):
    """the eight product_status arrays defined by CSAF 2.0 section 3.2.3.9."""

    FIRST_AFFECTED = "first_affected"
    FIRST_FIXED = "first_fixed"
    FIXED = "fixed"
    KNOWN_AFFECTED = "known_affected"
    KNOWN_NOT_AFFECTED = "known_not_affected"
    LAST_AFFECTED = "last_affected"
    RECOMMENDED = "recommended"
    UNDER_INVESTIGATION = "under_investigation"


@dataclass
class CSAFProduct:
    """one leaf of the flattened product tree."""

    product_id: str
    vendor: str
    product_name: str
    version_text: str
    version_range: VersionRange
    full_name: str = ""
    model_numbers: list[str] = field(default_factory=list)
    skus: list[str] = field(default_factory=list)
    cpe: str = ""

    vendor_key: str = ""
    key: ProductKey = field(init=False, repr=False, default=None)  # type: ignore[assignment]

    def __post_init__(self) -> None:
        self.vendor_key = canon_vendor(self.vendor)
        self.key = product_key(self.product_name, self.vendor)

    @property
    def product_key(self) -> str:
        return self.key.full


@dataclass
class CSAFVuln:
    cve: str
    cwe: str = ""
    title: str = ""
    cvss_score: float | None = None
    cvss_vector: str = ""
    known_affected: list[str] = field(default_factory=list)
    remediations: list[str] = field(default_factory=list)
    status: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class Advisory:
    advisory_id: str
    title: str
    published: str
    revised: str
    severity: str
    publisher: str
    summary: str
    products: list[CSAFProduct] = field(default_factory=list)
    vulns: list[CSAFVuln] = field(default_factory=list)
    sectors: list[str] = field(default_factory=list)
    source_path: str = ""
    tlp: str = ""

    _status_cache: dict[str, set[ProductStatus]] | None = field(
        init=False, repr=False, default=None
    )

    @property
    def cves(self) -> list[str]:
        return [v.cve for v in self.vulns if v.cve]

    @property
    def max_cvss(self) -> float | None:
        scores = [v.cvss_score for v in self.vulns if v.cvss_score is not None]
        return max(scores) if scores else None

    @property
    def has_patch(self) -> bool:
        """true if any vulnerability carries a vendor remediation."""
        return any(v.remediations for v in self.vulns)

    @property
    def base_id(self) -> str:
        """the id without any disambiguation suffix, for building URLs.

        two files in the CISA corpus can claim one tracking id while holding
        different advisories. both are kept, so the second carries a ~n
        suffix that must not reach a public link.
        """
        return self.advisory_id.split("~", 1)[0]

    def status_of(self, product_id: str) -> set[ProductStatus]:
        """every product_status this advisory records for one product."""
        if self._status_cache is None:
            cache: dict[str, set[ProductStatus]] = {}
            for v in self.vulns:
                for name, ids in v.status.items():
                    try:
                        st = ProductStatus(name)
                    except ValueError:
                        continue
                    for pid in ids:
                        cache.setdefault(pid, set()).add(st)
            self._status_cache = cache
        return self._status_cache.get(product_id, set())


_VERSION_CATEGORIES = {"product_version", "product_version_range"}


def _flatten_tree(
    branches: list[dict[str, Any]] | None,
    vendor: str = "",
    product: str = "",
) -> Iterator[CSAFProduct]:
    """walk the nested branch structure, one CSAFProduct per leaf.

    (vendor, product) context accumulates as we descend. product_family and
    product_name both contribute to the label; the deeper one wins because it
    is more specific.
    """
    for branch in branches or []:
        cat = branch.get("category", "")
        name = branch.get("name", "")

        v, p = vendor, product
        if cat == "vendor":
            v = name
        elif cat in ("product_name", "product_family"):
            p = name if not p or cat == "product_name" else f"{p} {name}"

        prod_obj = branch.get("product")
        if prod_obj:
            version_text = name if cat in _VERSION_CATEGORIES else ""
            helper = prod_obj.get("product_identification_helper", {}) or {}
            yield CSAFProduct(
                product_id=prod_obj.get("product_id", ""),
                vendor=v,
                product_name=p or prod_obj.get("name", ""),
                version_text=version_text,
                version_range=parse_range(version_text)
                if cat == "product_version_range"
                else _exact_range(version_text),
                full_name=prod_obj.get("name", ""),
                model_numbers=list(helper.get("model_numbers", []) or []),
                skus=list(helper.get("skus", []) or []),
                cpe=helper.get("cpe", "") or "",
            )

        yield from _flatten_tree(branch.get("branches"), v, p)


def _exact_range(version_text: str) -> VersionRange:
    """a product_version leaf is an exact pin, not a range."""
    if not version_text:
        return VersionRange(raw="", kind=RangeKind.UNPARSEABLE, note="no version on leaf")
    return parse_range(version_text)


def _best_cvss(scores: list[dict[str, Any]] | None) -> tuple[float | None, str]:
    """prefer CVSS v4 over v3 over v2, returning (score, vector)."""
    best: tuple[float | None, str] = (None, "")
    for entry in scores or []:
        for key in ("cvss_v4", "cvss_v3", "cvss_v2"):
            block = entry.get(key)
            if not block:
                continue
            score = block.get("baseScore")
            vector = block.get("vectorString", "")
            if score is None:
                continue
            if best[0] is None or float(score) > best[0]:
                best = (float(score), vector)
    return best


def _parse_vulns(raw: list[dict[str, Any]] | None) -> list[CSAFVuln]:
    out: list[CSAFVuln] = []
    for v in raw or []:
        score, vector = _best_cvss(v.get("scores"))
        status = v.get("product_status", {}) or {}
        rems = [
            r.get("details", "")
            for r in (v.get("remediations") or [])
            if r.get("category") in ("vendor_fix", "mitigation", "workaround")
        ]
        out.append(
            CSAFVuln(
                cve=v.get("cve", ""),
                cwe=(v.get("cwe") or {}).get("id", ""),
                title=v.get("title", ""),
                cvss_score=score,
                cvss_vector=vector,
                known_affected=list(status.get("known_affected", []) or []),
                remediations=[r for r in rems if r],
                status={k: list(ids or []) for k, ids in status.items()},
            )
        )
    return out


def _note(doc: dict[str, Any], category: str) -> str:
    for n in doc.get("notes", []) or []:
        if n.get("category") == category:
            return str(n.get("text", ""))
    return ""


def parse_advisory(path: Path | str) -> Advisory | None:
    """parse one CSAF JSON file. returns None on malformed input."""
    path = Path(path)
    try:
        with path.open(encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None

    doc = data.get("document", {}) or {}
    tracking = doc.get("tracking", {}) or {}
    publisher = doc.get("publisher", {}) or {}
    distribution = doc.get("distribution", {}) or {}

    sectors: list[str] = []
    for n in doc.get("notes", []) or []:
        if str(n.get("title", "")).lower().startswith("critical infrastructure"):
            sectors = [s.strip() for s in str(n.get("text", "")).split(",") if s.strip()]

    return Advisory(
        advisory_id=tracking.get("id", path.stem.upper()),
        title=doc.get("title", ""),
        published=tracking.get("initial_release_date", ""),
        revised=tracking.get("current_release_date", ""),
        severity=(doc.get("aggregate_severity") or {}).get("text", ""),
        publisher=publisher.get("name", ""),
        summary=_note(doc, "summary") or _note(doc, "general"),
        products=list(_flatten_tree((data.get("product_tree", {}) or {}).get("branches"))),
        vulns=_parse_vulns(data.get("vulnerabilities")),
        sectors=sectors,
        source_path=str(path),
        tlp=((distribution.get("tlp") or {}).get("label", "") or ""),
    )


def iter_advisory_files(root: Path | str) -> Iterator[Path]:
    """yield every .json under root, sorted for reproducible ingest."""
    yield from sorted(Path(root).rglob("*.json"))
