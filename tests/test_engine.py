"""match engine: status gating, range scoping, index reuse, tie-breaks."""

from __future__ import annotations

from icsmatch.ingest.csaf import Advisory
from icsmatch.match.engine import Asset, CorpusIndex, Tier, Verdict, match_assets

from .factories import advisory, product

# CSAF product_status


def test_known_not_affected_suppresses_the_finding() -> None:
    asset = Asset(asset_id="A1", vendor="Siemens", product="SIMATIC S7-1200")
    adv = advisory(
        [product("SIMATIC S7-1200")],
        status={"known_not_affected": ["CSAFPID-0001"]},
    )
    assert match_assets([asset], [adv], min_tier=Tier.VENDOR) == []


def test_fixed_status_suppresses_the_finding() -> None:
    asset = Asset(asset_id="A1", vendor="Siemens", product="SIMATIC S7-1200")
    adv = advisory([product("SIMATIC S7-1200")], status={"fixed": ["CSAFPID-0001"]})
    assert match_assets([asset], [adv], min_tier=Tier.VENDOR) == []


def test_under_investigation_downgrades_to_unknown() -> None:
    asset = Asset(asset_id="A1", vendor="Siemens", product="SIMATIC S7-1200")
    adv = advisory(
        [product("SIMATIC S7-1200")],
        status={"under_investigation": ["CSAFPID-0001"]},
    )
    matches = match_assets([asset], [adv], min_tier=Tier.VENDOR)
    assert matches and matches[0].verdict is Verdict.UNKNOWN
    assert "under investigation" in matches[0].basis


def test_missing_status_block_is_not_treated_as_not_affected() -> None:
    asset = Asset(asset_id="A1", vendor="Siemens", product="SIMATIC S7-1200")
    adv = advisory([product("SIMATIC S7-1200")], status={})
    assert match_assets([asset], [adv], min_tier=Tier.VENDOR)


# version range scoping


def test_component_scoped_range_does_not_judge_the_firmware_column() -> None:
    """a BIOS constraint says nothing about the version an inventory tracks."""
    asset = Asset(asset_id="A1", vendor="Siemens", product="SIMATIC S7-1200", version="1.0")
    adv = advisory([product("SIMATIC S7-1200", version="<BIOS_V2.0")])
    matches = match_assets([asset], [adv], min_tier=Tier.EXACT)
    assert matches and matches[0].verdict is Verdict.UNKNOWN
    assert "BIOS" in matches[0].basis


def test_version_out_of_range_drops_the_match() -> None:
    asset = Asset(asset_id="A1", vendor="Siemens", product="SIMATIC S7-1200", version="9.9")
    adv = advisory([product("SIMATIC S7-1200", version="<V4.5")])
    assert match_assets([asset], [adv], min_tier=Tier.EXACT) == []


# index reuse


def test_prebuilt_index_gives_identical_results() -> None:
    assets = [
        Asset(asset_id="A1", vendor="Siemens", product="SIMATIC S7-1200", version="4.2"),
        Asset(asset_id="A2", vendor="Siemens", product="SCALANCE X208", version="4.5"),
    ]
    advisories = [
        advisory([product("SIMATIC S7-1200", version="<V4.5")], aid="ICSA-A"),
        advisory([product("SCALANCE XF208", version="<V5.2.5")], aid="ICSA-B"),
    ]
    direct = match_assets(assets, advisories, min_tier=Tier.VENDOR)
    reused = match_assets(assets, CorpusIndex(advisories), min_tier=Tier.VENDOR)
    assert [(m.asset.asset_id, m.advisory.advisory_id, m.tier) for m in direct] == [
        (m.asset.asset_id, m.advisory.advisory_id, m.tier) for m in reused
    ]


def test_one_row_per_asset_advisory_pair() -> None:
    """a many-product advisory yields one row per asset, not one per product."""
    products = [
        product("SIMATIC S7-1200", pid=f"CSAFPID-{i:04d}") for i in range(1, 25)
    ]
    asset = Asset(asset_id="A1", vendor="Siemens", product="SIMATIC S7-1200")
    matches = match_assets([asset], [advisory(products)], min_tier=Tier.VENDOR)
    assert len(matches) == 1


# a not-affected leaf must not displace a real finding on the same advisory


def _two_leaf_advisory() -> Advisory:
    """one advisory naming the same asset twice: one leaf clear, one affected.

    the clear leaf matches on SKU (tier 1), the affected leaf only on
    vendor+product (tier 3), so tier order alone would pick the wrong one.
    """
    clear = product("SIMATIC S7-1200", "vers:all/*", pid="CSAFPID-0001")
    clear.model_numbers = ["6ES7214-1AG40-0XB0"]
    affected = product("SIMATIC S7-1200", "<V4.5", pid="CSAFPID-0002")
    return advisory(
        [clear, affected],
        status={
            "known_not_affected": ["CSAFPID-0001"],
            "known_affected": ["CSAFPID-0002"],
        },
    )


def _s7_asset() -> Asset:
    return Asset(
        asset_id="PLC-1",
        vendor="Siemens",
        product="SIMATIC S7-1200",
        version="4.2.1",
        model="6ES7214-1AG40-0XB0",
    )


def test_not_affected_leaf_does_not_hide_an_affected_leaf() -> None:
    index = CorpusIndex([_two_leaf_advisory()])
    found = match_assets([_s7_asset()], index, min_tier=Tier.VENDOR)
    assert len(found) == 1
    assert found[0].verdict is Verdict.AFFECTED
    assert found[0].product.product_id == "CSAFPID-0002"


def test_not_affected_is_still_reported_when_asked_for() -> None:
    index = CorpusIndex([_two_leaf_advisory()])
    found = match_assets(
        [_s7_asset()], index, min_tier=Tier.VENDOR, include_not_affected=True
    )
    verdicts = {m.verdict for m in found}
    assert Verdict.AFFECTED in verdicts


def test_a_wholly_clear_advisory_yields_no_finding() -> None:
    clear = product("SIMATIC S7-1200", "vers:all/*", pid="CSAFPID-0001")
    adv = advisory([clear], status={"known_not_affected": ["CSAFPID-0001"]})
    index = CorpusIndex([adv])
    assert match_assets([_s7_asset()], index, min_tier=Tier.VENDOR) == []
    kept = match_assets(
        [_s7_asset()], index, min_tier=Tier.VENDOR, include_not_affected=True
    )
    assert len(kept) == 1
    assert kept[0].verdict is Verdict.NOT_AFFECTED
