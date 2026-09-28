"""product name normalisation and key agreement."""

from __future__ import annotations

import pytest

from icsmatch.match.engine import Asset, CorpusIndex, Tier, Verdict, match_assets
from icsmatch.normalize.product import is_low_entropy, keys_agree, product_key

from .factories import advisory, product

# product key collisions


@pytest.mark.parametrize(
    "asset_name,advisory_name",
    [
        ("SIPROTEC 5", "SICAM 5"),
        ("SICAM 5", "SIPROTEC 5"),
        ("MicroLogix 1400", "ControlLogix 1400"),
        ("SIMATIC S120", "SINAMICS S120"),
    ],
)
def test_different_brand_lines_never_assert_a_match(
    asset_name: str, advisory_name: str
) -> None:
    """two brand lines sharing a series number are not the same product."""
    asset = Asset(asset_id="A1", vendor="Siemens", product=asset_name)
    adv = advisory([product(advisory_name)])
    for m in match_assets([asset], [adv], min_tier=Tier.FUZZY):
        assert m.tier is not Tier.EXACT
        assert m.verdict is not Verdict.AFFECTED


def test_software_variant_is_not_the_hardwareproduct() -> None:
    """an S7-1500 CPU is not an S7-1500 Software Controller."""
    asset = Asset(asset_id="A1", vendor="Siemens", product="S7-1500", version="2.8")
    adv = advisory([product("SIMATIC S7-1500 Software Controller")])
    for m in match_assets([asset], [adv], min_tier=Tier.FUZZY):
        assert m.tier is not Tier.EXACT

    real = advisory([product("SIMATIC S7-1500 CPU family")])
    matches = match_assets([asset], [real], min_tier=Tier.EXACT)
    assert matches and matches[0].tier is Tier.EXACT


def test_descriptive_suffixes_are_still_ignored() -> None:
    """firmware, controllers and family carry no identity."""
    asset = Asset(asset_id="A1", vendor="Schneider Electric", product="Modicon M580")
    for name in ("Modicon M580 Firmware", "Modicon M580 CPU", "Modicon M580 controllers"):
        adv = advisory([product(name, vendor="Schneider Electric")])
        matches = match_assets([asset], [adv], min_tier=Tier.EXACT)
        assert matches and matches[0].tier is Tier.EXACT, name


def test_brandless_inventory_entry_still_matches() -> None:
    """an inventory that drops the brand line must still match the advisory."""
    asset = Asset(asset_id="A1", vendor="Siemens", product="S7-1200", version="4.2")
    adv = advisory([product("SIMATIC S7-1200 CPU family", version="<V4.5")])
    matches = match_assets([asset], [adv], min_tier=Tier.EXACT)
    assert matches and matches[0].tier is Tier.EXACT
    assert matches[0].verdict is Verdict.AFFECTED


def test_low_entropy_core_without_a_brand_goes_to_review() -> None:
    """a bare series number is a lead, never a confirmed finding."""
    asset = Asset(asset_id="A1", vendor="Rockwell", product="1400")
    adv = advisory([product("MicroLogix 1400", vendor="Rockwell Automation")])
    matches = match_assets([asset], [adv], min_tier=Tier.FUZZY)
    assert matches and matches[0].tier is Tier.FUZZY
    assert matches[0].verdict is Verdict.REVIEW
    assert "low-entropy" in matches[0].basis


def test_low_entropy_predicate() -> None:
    assert is_low_entropy("5")
    assert is_low_entropy("1400")
    assert is_low_entropy("cc")
    assert not is_low_entropy("s71200")
    assert not is_low_entropy("m580")


def test_keys_agree_contract() -> None:
    assert keys_agree(product_key("SIPROTEC 5"), product_key("SICAM 5")) is None
    assert keys_agree(product_key("S7-1200"), product_key("SIMATIC S7-1200")) == "exact"
    assert keys_agree(product_key("1400"), product_key("MicroLogix 1400")) == "weak"
    assert keys_agree(product_key(""), product_key("SIMATIC")) is None


# inventory hygiene


def test_unrecognised_row_is_flagged() -> None:
    assert not Asset.from_row({"name": "foo", "thing": "bar"}).recognised
    assert Asset.from_row({"vendor": "Siemens", "product": "S7-1200"}).recognised


def test_vendor_repeated_in_the_product_name_is_dropped() -> None:
    """advisories write the vendor twice, inventories write it once."""
    asset = Asset(asset_id="A1", vendor="Allen-Bradley", product="MicroLogix 1400")
    adv = advisory(
        [product("Allen-Bradley MicroLogix 1400 Controllers", vendor="Rockwell Automation")]
    )
    matches = match_assets([asset], [adv], min_tier=Tier.EXACT)
    assert matches and matches[0].tier is Tier.EXACT


def test_advisory_plural_matches_inventory_singular() -> None:
    asset = Asset(asset_id="A1", vendor="Siemens", product="SIMATIC HMI Comfort Panel")
    adv = advisory([product("SIMATIC HMI Comfort Panels")])
    matches = match_assets([asset], [adv], min_tier=Tier.EXACT)
    assert matches and matches[0].tier is Tier.EXACT


def test_scope_note_is_dropped_but_order_number_is_kept() -> None:
    assert product_key("SIMATIC S7-1500 CPU family (incl. related ET200 CPUs)").core == "s71500"
    assert "6es7518" in product_key("SIMATIC S7-1500 CPU 1518-4 (6ES7518-4AX00-1AB0)").core


def test_header_aliases_are_accepted() -> None:
    a = Asset.from_row(
        {"Manufacturer": "Siemens", "Device": "S7-1200", "Order Number": "6ES7", "Zone": "2"}
    )
    assert a.vendor_key == "siemens"
    assert a.model_key == "6es7"
    assert a.purdue_level == "2"


# a variant line is the parent line for matching purposes


def test_siplus_variant_matches_simaticadvisory() -> None:
    """advisories say "(incl. SIPLUS variants)" and the scope note is dropped,
    so the family has to be known to the key comparison instead."""
    adv = advisory([product("SIMATIC S7-1500 CPU family (incl. SIPLUS variants)", "<V2.9")])
    index = CorpusIndex([adv])
    for name in ("SIMATIC S7-1500", "SIPLUS S7-1500"):
        asset = Asset(asset_id="A", vendor="Siemens", product=name, version="2.8")
        found = match_assets([asset], index, min_tier=Tier.EXACT)
        assert len(found) == 1, name
        assert found[0].verdict is Verdict.AFFECTED


def test_brand_family_does_not_leak_to_unrelated_brands() -> None:
    assert keys_agree(product_key("SINAMICS S120"), product_key("SIMATIC S120")) is None
    assert keys_agree(product_key("SIPROTEC 5"), product_key("SICAM 5")) is None


# rapidfuzz does not depend on numpy, so the fuzzy path must not either


def test_fuzzy_batch_works_without_numpy(monkeypatch: pytest.MonkeyPatch) -> None:
    """process.cdist imports numpy lazily; process.extract does not.

    a plain `pip install rapidfuzz` brings no numpy, so a cdist-based scorer
    raises ModuleNotFoundError at match time on a clean install.
    """
    import builtins

    from icsmatch.normalize.product import HAVE_RAPIDFUZZ, fuzzy_batch

    if not HAVE_RAPIDFUZZ:
        pytest.skip("rapidfuzz not installed")

    real_import = builtins.__import__

    def blocked(name: str, *a: object, **k: object) -> object:
        if name == "numpy" or name.startswith("numpy."):
            raise ModuleNotFoundError("No module named 'numpy'")
        return real_import(name, *a, **k)  # type: ignore[arg-type]

    monkeypatch.setattr(builtins, "__import__", blocked)
    hits = fuzzy_batch("scalancex208", ["scalancexf208", "simatics71200", ""], 0.82)
    assert hits == [(0, 0.96)]


def test_fuzzy_batch_indexes_refer_to_the_input_list() -> None:
    from icsmatch.normalize.product import fuzzy_batch

    choices = ["simatics71200", "scalancexf208", "modiconm580"]
    for idx, ratio in fuzzy_batch("scalancex208", choices, 0.82):
        assert choices[idx] == "scalancexf208"
        assert 0.82 <= ratio <= 1.0
