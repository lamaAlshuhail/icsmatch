"""match engine and normaliation tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from icsmatch.ingest.csaf import Advisory, CSAFProduct, CSAFVuln
from icsmatch.match.engine import Asset, Tier, Verdict, match_assets
from icsmatch.normalize.product import canon_product, canon_vendor
from icsmatch.normalize.versions import parse_range

# ---------------------------------------------------------------------------
# normalisation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "a,b",
    [
        ("Siemens", "Siemens AG"),
        ("SIEMENS", "siemens ag"),
        ("Rockwell Automation", "Allen-Bradley"),
        ("Schneider Electric", "Modicon"),
        ("Hitachi Energy", "Hitachi ABB Power Grids"),
        # Regression: division suffixes split one vendor across two keys.
        # "Schneider Electric Software, LLC" appears on 197 products in the
        # CISA corpus and must not become a separate vendor.
        ("Schneider Electric", "Schneider Electric Software, LLC"),
        ("Rockwell Automation", "Rockwell Automation, Inc."),
        ("GE", "GE Vernova"),
    ],
)
def test_vendor_aliases_collapse(a: str, b: str) -> None:
    assert canon_vendor(a) == canon_vendor(b)


@pytest.mark.parametrize(
    "a,b",
    [
        ("SIMATIC S7-1200", "S7-1200"),
        ("SIMATIC S7-1200 CPU family", "S7 1200"),
        ("MicroLogix 1400 Controllers", "MicroLogix 1400"),
        ("SCALANCE X200", "X200"),
    ],
)
def test_product_normalisation_collapses(a: str, b: str) -> None:
    assert canon_product(a) == canon_product(b)


def test_distinct_products_stay_distinct() -> None:
    """Normalisation must not over-collapse."""
    assert canon_product("S7-1200") != canon_product("S7-1500")
    assert canon_vendor("Siemens") != canon_vendor("Schneider Electric")


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------

def _advisory(products: list[CSAFProduct], cvss: float = 7.5) -> Advisory:
    return Advisory(
        advisory_id="ICSA-TEST-01",
        title="Test Advisory",
        published="2026-01-01",
        revised="2026-01-01",
        severity="HIGH",
        publisher="CISA",
        summary="test",
        products=products,
        vulns=[
            CSAFVuln(
                cve="CVE-2026-0001",
                cvss_score=cvss,
                known_affected=[p.product_id for p in products],
                remediations=["upgrade"],
            )
        ],
    )


def _product(
    vendor: str = "Siemens",
    name: str = "SIMATIC S7-1200",
    version: str = "<V4.5",
    pid: str = "CSAFPID-0001",
    models: list[str] | None = None,
    cpe: str = "",
) -> CSAFProduct:
    return CSAFProduct(
        product_id=pid,
        vendor=vendor,
        product_name=name,
        version_text=version,
        version_range=parse_range(version),
        model_numbers=models or [],
        cpe=cpe,
    )


# ---------------------------------------------------------------------------
# tier cascade
# ---------------------------------------------------------------------------

def test_tier1_sku_beats_everything() -> None:
    """model/SKU match wins even when the product name disagrees.

    this is the case CPE cannot express: the inventory says "PLC" but the
    order number is exact.
    """
    asset = Asset(asset_id="A1", vendor="Siemens", product="Unknown PLC",
                  version="4.2", model="6ES7214-1AG40-0XB0")
    adv = _advisory([_product(models=["6ES7214-1AG40-0XB0"])])

    matches = match_assets([asset], [adv])
    assert len(matches) == 1
    assert matches[0].tier is Tier.SKU
    assert matches[0].confidence == 1.0
    assert matches[0].verdict is Verdict.AFFECTED


def test_tier1_sku_proves_identity_not_vulnerability() -> None:
    """the same device on firmware past every fix is not affected.

    a model number identifies the hardware. whether that hardware is
    vulnerable is the version range's job, and tier 1 must not skip it.
    """
    asset = Asset(asset_id="A1", vendor="Siemens", product="Unknown PLC",
                  version="9.9", model="6ES7214-1AG40-0XB0")
    adv = _advisory([_product(version="<V4.5", models=["6ES7214-1AG40-0XB0"])])

    assert match_assets([asset], [adv]) == []
    kept = match_assets([asset], [adv], include_not_affected=True)
    assert len(kept) == 1
    assert kept[0].tier is Tier.SKU
    assert kept[0].verdict is Verdict.NOT_AFFECTED
    assert "outside" in kept[0].basis


def test_tier1_sku_with_unparseable_range_is_unknown_not_affected() -> None:
    asset = Asset(asset_id="A1", vendor="Siemens", product="PLC",
                  version="4.2", model="6ES7214-1AG40-0XB0")
    adv = _advisory([_product(version="< V15.1 Upd 4", models=["6ES7214-1AG40-0XB0"])])

    m = match_assets([asset], [adv])[0]
    assert m.tier is Tier.SKU
    assert m.verdict is Verdict.UNKNOWN
    assert m.confidence < 1.0


def test_tier1_sku_without_asset_version_still_asserts() -> None:
    """no version in the inventory means nothing to gate on."""
    asset = Asset(asset_id="A1", vendor="Siemens", product="PLC",
                  version="", model="6ES7214-1AG40-0XB0")
    adv = _advisory([_product(version="<V4.5", models=["6ES7214-1AG40-0XB0"])])

    m = match_assets([asset], [adv])[0]
    assert m.verdict is Verdict.AFFECTED
    assert m.confidence == 1.0


def test_tier3_exact_product_and_version() -> None:
    asset = Asset(asset_id="A1", vendor="Siemens", product="S7-1200", version="4.2.1")
    adv = _advisory([_product(version="<V4.5")])

    m = match_assets([asset], [adv])[0]
    assert m.tier is Tier.EXACT
    assert m.verdict is Verdict.AFFECTED
    assert "4.2.1" in m.basis


def test_version_out_of_range_is_not_a_match() -> None:
    """The most important negative case."""
    asset = Asset(asset_id="A1", vendor="Siemens", product="S7-1200", version="5.0")
    adv = _advisory([_product(version="<V4.5")])

    assert match_assets([asset], [adv], min_tier=Tier.EXACT) == []


def test_unparseable_range_yields_unknown_not_silence() -> None:
    """An unparseable range must surface, not disappear."""
    asset = Asset(asset_id="A1", vendor="Siemens", product="S7-1200", version="4.2")
    adv = _advisory([_product(version="<=Build 16102416")])

    m = match_assets([asset], [adv])[0]
    assert m.verdict is Verdict.UNKNOWN
    assert m.confidence < 0.85


def test_wrong_vendor_never_matches() -> None:
    asset = Asset(asset_id="A1", vendor="Schneider Electric", product="S7-1200", version="4.2")
    adv = _advisory([_product(vendor="Siemens")])

    assert match_assets([asset], [adv]) == []


def test_vendor_only_is_tier5_manual() -> None:
    asset = Asset(asset_id="A1", vendor="Siemens", product="Totally Different Box", version="1.0")
    adv = _advisory([_product(name="SIMATIC S7-1200")])

    m = match_assets([asset], [adv], min_tier=Tier.VENDOR)[0]
    assert m.tier is Tier.VENDOR
    assert m.verdict is Verdict.MANUAL


def test_min_tier_filters_weak_matches() -> None:
    asset = Asset(asset_id="A1", vendor="Siemens", product="Totally Different Box", version="1.0")
    adv = _advisory([_product()])

    assert match_assets([asset], [adv], min_tier=Tier.EXACT) == []
    assert len(match_assets([asset], [adv], min_tier=Tier.VENDOR)) == 1


def test_one_match_per_asset_advisory_pair() -> None:
    """A 3-product advisory must not produce 3 rows for one asset."""
    asset = Asset(asset_id="A1", vendor="Siemens", product="S7-1200", version="4.2.1")
    adv = _advisory([
        _product(pid="CSAFPID-0001", version="<V4.5"),
        _product(pid="CSAFPID-0002", version="<V4.4"),
        _product(pid="CSAFPID-0003", version="vers:all/*"),
    ])

    assert len(match_assets([asset], [adv])) == 1


def test_cves_scoped_to_matched_product() -> None:
    """Only CVEs naming this product_id should be reported."""
    p1 = _product(pid="CSAFPID-0001")
    p2 = _product(pid="CSAFPID-0002", name="SIMATIC S7-1500")
    adv = Advisory(
        advisory_id="ICSA-TEST-02", title="t", published="", revised="",
        severity="HIGH", publisher="CISA", summary="",
        products=[p1, p2],
        vulns=[
            CSAFVuln(cve="CVE-2026-1111", cvss_score=9.0, known_affected=["CSAFPID-0001"]),
            CSAFVuln(cve="CVE-2026-2222", cvss_score=5.0, known_affected=["CSAFPID-0002"]),
        ],
    )
    asset = Asset(asset_id="A1", vendor="Siemens", product="S7-1200", version="4.2")

    m = match_assets([asset], [adv])[0]
    assert m.cves == ["CVE-2026-1111"]
    assert m.cvss == 9.0


# ---------------------------------------------------------------------------
# asset CSV tolerance
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "row",
    [
        {"asset_id": "A1", "vendor": "Siemens", "product": "S7-1200", "version": "4.2"},
        {"id": "A1", "manufacturer": "Siemens", "device": "S7-1200", "firmware": "4.2"},
        {"tag": "A1", "make": "Siemens", "product_name": "S7-1200", "fw": "4.2"},
    ],
)
def test_asset_from_row_tolerates_header_variants(row: dict[str, str]) -> None:
    a = Asset.from_row(row)
    assert a.asset_id == "A1"
    assert a.vendor_key == "siemens"
    assert a.product_key == canon_product("S7-1200")
    assert a.parsed_version is not None


def test_stdlib_fallback_covers_every_yaml_vendor_alias() -> None:
    """the core is advertised as stdlib-only, so no alias may need PyYAML.

    without this guard a contributor adds a vendor to normalizers.yaml, the
    suite passes on a dev machine, and an air-gapped install silently misses
    the vendor.
    """
    yaml = pytest.importorskip("yaml")
    from icsmatch.normalize.product import _VENDOR_ALIASES

    path = Path(__file__).resolve().parents[1] / "data" / "normalizers.yaml"
    if not path.exists():
        pytest.skip("normalizers.yaml not present")
    with path.open(encoding="utf-8") as fh:
        declared = (yaml.safe_load(fh) or {}).get("vendor_aliases", {})

    missing: dict[str, list[str]] = {}
    for key, aliases in declared.items():
        builtin = {a.lower() for a in _VENDOR_ALIASES.get(key, [])}
        gap = [a for a in aliases if a.lower() not in builtin]
        if gap:
            missing[key] = gap
    assert not missing, f"aliases unreachable without PyYAML: {missing}"
