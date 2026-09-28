"""test factories shared across modules."""

from __future__ import annotations

from icsmatch.ingest.csaf import Advisory, CSAFProduct, CSAFVuln
from icsmatch.normalize.versions import parse_range


def product(
    name: str,
    version: str = "vers:all/*",
    vendor: str = "Siemens",
    pid: str = "CSAFPID-0001",
) -> CSAFProduct:
    return CSAFProduct(
        product_id=pid,
        vendor=vendor,
        product_name=name,
        version_text=version,
        version_range=parse_range(version),
    )


def advisory(
    products: list[CSAFProduct],
    cvss: float = 9.8,
    status: dict[str, list[str]] | None = None,
    aid: str = "ICSA-TEST-01",
) -> Advisory:
    known = [p.product_id for p in products]
    return Advisory(
        advisory_id=aid,
        title="Test Advisory",
        published="2026-01-01",
        revised="2026-01-01",
        severity="CRITICAL",
        publisher="CISA",
        summary="",
        products=products,
        vulns=[
            CSAFVuln(
                cve="CVE-2026-0001",
                cvss_score=cvss,
                known_affected=known,
                remediations=["upgrade"],
                status=status if status is not None else {"known_affected": known},
            )
        ],
    )
