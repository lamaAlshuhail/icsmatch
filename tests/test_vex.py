"""OpenVEX export."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from icsmatch.ingest.csaf import Advisory, CSAFProduct, CSAFVuln
from icsmatch.match.engine import Asset, Match, Tier, Verdict
from icsmatch.normalize.versions import parse_range
from icsmatch.report.vex import VEX_CONTEXT, Justification, render_vex

VALID_STATUSES = {"not_affected", "affected", "fixed", "under_investigation"}
VALID_JUSTIFICATIONS = {
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
}
STAMP = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


def _product(pid: str = "P1", name: str = "SIMATIC S7-1200") -> CSAFProduct:
    return CSAFProduct(
        product_id=pid,
        vendor="Siemens",
        product_name=name,
        version_text="<V4.5",
        version_range=parse_range("<V4.5"),
    )


def _advisory(aid: str, cves: list[str], pid: str = "P1") -> Advisory:
    return Advisory(
        advisory_id=aid,
        title=f"{aid} title",
        published="2026-01-01",
        revised="2026-01-01",
        severity="high",
        publisher="CISA",
        summary="",
        products=[_product(pid)],
        vulns=[
            CSAFVuln(cve=c, cvss_score=7.5, known_affected=[pid]) for c in cves
        ],
    )


def _match(verdict: Verdict, *, aid: str = "ICSA-26-001-01", cve: str = "CVE-2026-1",
           asset_id: str = "PLC-1", basis: str = "vendor+product match",
           tier: Tier = Tier.EXACT) -> Match:
    adv = _advisory(aid, [cve])
    asset = Asset(
        asset_id=asset_id,
        vendor="Siemens",
        product="SIMATIC S7-1200",
        version="4.2.1",
        model="6ES7214-1AG40-0XB0",
    )
    return Match(
        asset=asset,
        advisory=adv,
        product=adv.products[0],
        tier=tier,
        confidence=0.85,
        verdict=verdict,
        basis=basis,
    )


def _doc(matches: list[Match]) -> dict:
    return json.loads(render_vex(matches, now=STAMP))


def test_document_shape() -> None:
    d = _doc([_match(Verdict.AFFECTED)])
    assert d["@context"] == VEX_CONTEXT
    assert d["@id"].startswith("https://openvex.dev/docs/icsmatch/vex-")
    assert d["timestamp"] == "2026-01-02T03:04:05+00:00"
    assert d["version"] == 1
    assert d["author"] == "icsmatch"


@pytest.mark.parametrize(
    "verdict,expected",
    [
        (Verdict.AFFECTED, "affected"),
        (Verdict.NOT_AFFECTED, "not_affected"),
        (Verdict.REVIEW, "under_investigation"),
        (Verdict.MANUAL, "under_investigation"),
        (Verdict.UNKNOWN, "under_investigation"),
    ],
)
def test_status_mapping(verdict: Verdict, expected: str) -> None:
    d = _doc([_match(verdict)])
    assert d["statements"][0]["status"] == expected


def test_every_status_is_in_the_openvex_vocabulary() -> None:
    matches = [_match(v, cve=f"CVE-2026-{i}") for i, v in enumerate(Verdict, start=1)]
    for stmt in _doc(matches)["statements"]:
        assert stmt["status"] in VALID_STATUSES


def test_not_affected_carries_a_valid_justification() -> None:
    d = _doc([_match(Verdict.NOT_AFFECTED)])
    stmt = d["statements"][0]
    assert stmt["justification"] in VALID_JUSTIFICATIONS
    assert "impact_statement" in stmt


def test_analyst_rejection_is_component_not_present(tmp_path) -> None:
    """end to end through the decision store, not a hand-built Match.

    the engine used to drop rejected pairs entirely, which made this path
    unreachable: a test that constructed the Match by hand passed anyway.
    """
    from icsmatch.match.engine import CorpusIndex, match_assets
    from icsmatch.store.decisions import Decision as D
    from icsmatch.store.decisions import DecisionStore

    adv = _advisory("ICSA-26-001-01", ["CVE-2026-1"])
    asset = Asset(asset_id="PLC-1", vendor="Siemens", product="SIMATIC S7-1200",
                  version="4.2.1", model="")
    with DecisionStore(tmp_path / "d.db") as store:
        store.record(
            vendor_key=asset.vendor_key,
            asset_product_key=asset.product_key,
            adv_product_key=adv.products[0].product_key,
            decision=D.REJECTED,
            analyst="L.A",
        )
        aliases = store.load()

    index = CorpusIndex([adv])
    assert match_assets([asset], index, aliases=aliases) == [], "reports hide it"
    kept = match_assets([asset], index, aliases=aliases, include_not_affected=True)
    assert len(kept) == 1
    assert kept[0].verdict is Verdict.NOT_AFFECTED

    stmt = _doc(kept)["statements"][0]
    assert stmt["status"] == "not_affected"
    assert stmt["justification"] == Justification.COMPONENT_NOT_PRESENT


def test_affected_has_no_justification() -> None:
    stmt = _doc([_match(Verdict.AFFECTED)])["statements"][0]
    assert "justification" not in stmt


def test_one_cve_across_assets_groups_into_one_statement() -> None:
    matches = [
        _match(Verdict.AFFECTED, asset_id="PLC-1"),
        _match(Verdict.AFFECTED, asset_id="PLC-2"),
        _match(Verdict.AFFECTED, asset_id="PLC-3"),
    ]
    d = _doc(matches)
    assert len(d["statements"]) == 1
    assert len(d["statements"][0]["products"]) == 3


def test_same_asset_twice_is_deduplicated() -> None:
    matches = [_match(Verdict.AFFECTED, asset_id="PLC-1")] * 2
    assert len(_doc(matches)["statements"][0]["products"]) == 1


def test_differing_status_splits_statements() -> None:
    d = _doc(
        [
            _match(Verdict.AFFECTED, asset_id="PLC-1"),
            _match(Verdict.NOT_AFFECTED, asset_id="PLC-2"),
        ]
    )
    assert len(d["statements"]) == 2
    assert {s["status"] for s in d["statements"]} == {"affected", "not_affected"}


def test_product_carries_a_purl_and_model_number() -> None:
    prod = _doc([_match(Verdict.AFFECTED)])["statements"][0]["products"][0]
    assert prod["@id"] == "urn:icsmatch:asset:PLC-1"
    assert prod["identifiers"]["purl"] == "pkg:generic/siemens/simatic-s7-1200@4.2.1"
    assert prod["identifiers"]["model_number"] == "6ES7214-1AG40-0XB0"


def test_empty_input_is_a_valid_empty_document() -> None:
    d = _doc([])
    assert d["statements"] == []
    assert d["@context"] == VEX_CONTEXT


def test_output_is_stable_for_the_same_input() -> None:
    a = render_vex([_match(Verdict.AFFECTED)], now=STAMP)
    b = render_vex([_match(Verdict.AFFECTED)], now=STAMP)
    assert a == b
