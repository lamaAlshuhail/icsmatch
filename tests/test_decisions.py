"""tests for the analyst feedback loop and the portfolio view."""

from __future__ import annotations

from pathlib import Path

import pytest

from icsmatch.ingest.csaf import Advisory, CSAFProduct, CSAFVuln
from icsmatch.ingest.enrich import Enrichment, Priority
from icsmatch.match.engine import Asset, Tier, Verdict, match_assets
from icsmatch.normalize.product import canon_vendor, product_key
from icsmatch.normalize.versions import parse_range
from icsmatch.report.markdown import render_markdown, score_matches
from icsmatch.report.portfolio import ClientResult, render_portfolio
from icsmatch.store.decisions import Decision, DecisionStore, LearnedAlias

# fixtures


def _product(name: str = "SIMATIC S7-1200", version: str = "<V4.5") -> CSAFProduct:
    return CSAFProduct(
        product_id="CSAFPID-0001",
        vendor="Siemens",
        product_name=name,
        version_text=version,
        version_range=parse_range(version),
    )


def _advisory(products: list[CSAFProduct], cvss: float = 9.8) -> Advisory:
    return Advisory(
        advisory_id="ICSA-TEST-01",
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
                known_affected=[p.product_id for p in products],
                remediations=["upgrade"],
            )
        ],
    )


def _key(name: str) -> str:
    """the stored form of a product key: brand plus core."""
    return product_key(name).full


@pytest.fixture
def store(tmp_path: Path) -> DecisionStore:
    return DecisionStore(tmp_path / "decisions.db")


# decision store


def test_decision_roundtrip(store: DecisionStore) -> None:
    store.record(
        vendor_key="siemens",
        asset_product_key="scalancex208",
        adv_product_key="scalancexf208",
        decision=Decision.CONFIRMED,
        analyst="L.Alshuhail",
        asset_product_raw="SCALANCE X208",
        adv_product_raw="SCALANCE XF208",
    )
    loaded = store.load()
    alias = loaded[("siemens", "scalancex208", "scalancexf208")]
    assert alias.decision is Decision.CONFIRMED
    assert alias.analyst == "L.Alshuhail"
    assert "SCALANCE X208" in alias.basis
    assert "L.Alshuhail" in alias.basis


def test_decision_is_idempotent(store: DecisionStore) -> None:
    """re-deciding a pair overwrites rather than duplicating."""
    for decision in (Decision.CONFIRMED, Decision.REJECTED):
        store.record(
            vendor_key="siemens",
            asset_product_key="a",
            adv_product_key="b",
            decision=decision,
        )
    loaded = store.load()
    assert len(loaded) == 1
    assert loaded[("siemens", "a", "b")].decision is Decision.REJECTED


def test_export_aliases_only_confirmed(store: DecisionStore) -> None:
    store.record(
        vendor_key="siemens", asset_product_key="a", adv_product_key="b",
        decision=Decision.CONFIRMED, asset_product_raw="A", adv_product_raw="B",
    )
    store.record(
        vendor_key="siemens", asset_product_key="c", adv_product_key="d",
        decision=Decision.REJECTED, asset_product_raw="C", adv_product_raw="D",
    )
    exported = store.export_aliases()
    assert len(exported) == 1
    assert exported[0]["asset_product"] == "A"


# tier 0 behaviour


def test_confirmed_alias_promotes_to_tier0() -> None:
    """a fuzzy pair a human confirmed is never re-litigated."""
    asset = Asset(asset_id="SW-021", vendor="Siemens", product="SCALANCE X208", version="4.5")
    adv = _advisory([_product(name="SCALANCE XF208", version="<V5.2.5")])

    plain = match_assets([asset], [adv], min_tier=Tier.FUZZY)
    assert plain and plain[0].tier is Tier.FUZZY

    aliases = {
        (canon_vendor("Siemens"), _key("SCALANCE X208"), _key("SCALANCE XF208")):
        LearnedAlias(
            vendor_key=canon_vendor("Siemens"),
            asset_product_key=_key("SCALANCE X208"),
            adv_product_key=_key("SCALANCE XF208"),
            decision=Decision.CONFIRMED,
            analyst="tester",
            asset_product_raw="SCALANCE X208",
            adv_product_raw="SCALANCE XF208",
        )
    }
    promoted = match_assets([asset], [adv], min_tier=Tier.FUZZY, aliases=aliases)
    assert promoted[0].tier is Tier.ALIAS
    assert promoted[0].confidence == 1.0
    assert promoted[0].verdict is Verdict.AFFECTED
    assert "analyst-confirmed" in promoted[0].basis


def test_rejected_alias_suppresses_match() -> None:
    """once rejected, a pair stops appearing."""
    asset = Asset(asset_id="A1", vendor="Siemens", product="SCALANCE X208", version="4.5")
    adv = _advisory([_product(name="SCALANCE XF208", version="<V5.2.5")])

    aliases = {
        (canon_vendor("Siemens"), _key("SCALANCE X208"), _key("SCALANCE XF208")):
        LearnedAlias(
            vendor_key=canon_vendor("Siemens"),
            asset_product_key=_key("SCALANCE X208"),
            adv_product_key=_key("SCALANCE XF208"),
            decision=Decision.REJECTED,
        )
    }
    assert match_assets([asset], [adv], min_tier=Tier.VENDOR, aliases=aliases) == []


def test_confirmed_alias_still_respects_version_range() -> None:
    """confirming identity does not confirm the version."""
    asset = Asset(asset_id="A1", vendor="Siemens", product="SCALANCE X208", version="9.9")
    adv = _advisory([_product(name="SCALANCE XF208", version="<V5.2.5")])

    aliases = {
        (canon_vendor("Siemens"), _key("SCALANCE X208"), _key("SCALANCE XF208")):
        LearnedAlias(
            vendor_key=canon_vendor("Siemens"),
            asset_product_key=_key("SCALANCE X208"),
            adv_product_key=_key("SCALANCE XF208"),
            decision=Decision.CONFIRMED,
        )
    }
    # 9.9 is outside <V5.2.5, so identity is confirmed but the version excludes it
    assert match_assets([asset], [adv], min_tier=Tier.VENDOR, aliases=aliases) == []


# portfolio


def _client(name: str, cvss: float, n_assets: int = 5) -> ClientResult:
    asset = Asset(asset_id="A1", vendor="Siemens", product="S7-1200", version="4.2")
    adv = _advisory([_product()], cvss=cvss)
    matches = match_assets([asset], [adv])
    scored = score_matches(matches, Enrichment(kev=set(), epss={}))
    return ClientResult(name=name, asset_count=n_assets, scored=scored, report_path=f"{name}.md")


def test_portfolio_orders_by_urgency() -> None:
    kev = Enrichment(kev={"CVE-2026-0001"}, epss={})
    asset = Asset(asset_id="A1", vendor="Siemens", product="S7-1200", version="4.2")
    urgent = ClientResult(
        name="urgent-client",
        asset_count=3,
        scored=score_matches(match_assets([asset], [_advisory([_product()])]), kev),
    )
    calm = _client("calm-client", cvss=5.0)

    md = render_portfolio([calm, urgent])
    assert md.index("urgent-client") < md.index("calm-client")
    assert "Inventories needing immediate action" in md


def test_portfolio_flags_cross_client_advisories() -> None:
    md = render_portfolio([_client("alpha", 9.8), _client("beta", 9.8)])
    assert "ICSA-TEST-01" in md
    assert "Shared exposure" in md


def test_portfolio_does_not_leak_asset_ids() -> None:
    """one inventory must not see another inventory's asset identifiers."""
    a = _client("alpha", 9.8)
    a.scored[0].match.asset.asset_id = "SECRET-ASSET-42"
    md = render_portfolio([a, _client("beta", 7.0)])
    assert "SECRET-ASSET-42" not in md


# report rendering


def test_kev_drives_now_priority() -> None:
    asset = Asset(asset_id="A1", vendor="Siemens", product="S7-1200", version="4.2")
    matches = match_assets([asset], [_advisory([_product()], cvss=5.0)])

    plain = score_matches(matches, Enrichment(kev=set(), epss={}))
    assert plain[0].priority is not Priority.NOW

    kev = score_matches(matches, Enrichment(kev={"CVE-2026-0001"}, epss={}))
    assert kev[0].priority is Priority.NOW
    assert "KEV" in kev[0].rationale


def test_empty_report_is_still_valid_markdown() -> None:
    md = render_markdown([], client="Nobody", total_assets=0, total_advisories=100)
    assert md.startswith("# ICS Advisory Triage")
    assert "No advisories matched" in md
