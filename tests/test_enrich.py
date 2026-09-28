"""prioritisation and exploitation signals."""

from __future__ import annotations

from icsmatch.ingest.enrich import Enrichment, Priority, decide

# prioritisation


def test_kev_is_immediate() -> None:
    d = decide(
        cves=["CVE-1"],
        cvss=5.0,
        enrichment=Enrichment(kev={"CVE-1"}, epss={}),
        has_patch=True,
        purdue_level="3",
    )
    assert d.priority is Priority.NOW
    assert d.vector.startswith("SSVCv2/E:A")
    assert d.vector.endswith("/D:I")


def test_no_patch_becomes_track_not_next() -> None:
    d = decide(
        cves=["CVE-1"],
        cvss=8.0,
        enrichment=Enrichment(kev=set(), epss={}),
        has_patch=False,
        purdue_level="2",
    )
    assert d.priority is Priority.TRACK
    assert "compensating controls" in d.rationale


def test_kev_outranks_a_missing_patch() -> None:
    d = decide(
        cves=["CVE-1"],
        cvss=8.0,
        enrichment=Enrichment(kev={"CVE-1"}, epss={}),
        has_patch=False,
        purdue_level="2",
    )
    assert d.priority is Priority.NOW


def test_exposure_changes_the_decision() -> None:
    common = {
        "cves": ["CVE-1"],
        "cvss": 6.0,
        "enrichment": Enrichment(kev=set(), epss={}),
        "has_patch": True,
    }
    deep = decide(purdue_level="1", **common)
    edge = decide(purdue_level="4", **common)
    assert deep.exposure == "small"
    assert edge.exposure == "open"
    assert deep.priority is Priority.LATER
    assert edge.priority is Priority.NEXT


def test_automatable_read_from_the_cvss_vector() -> None:
    common = {
        "cves": ["CVE-1"],
        "cvss": 6.5,
        "enrichment": Enrichment(kev=set(), epss={"CVE-1": 0.5}),
        "has_patch": True,
        "purdue_level": "2",
    }
    auto = decide(cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", **common)
    manual = decide(cvss_vector="CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L", **common)
    assert auto.utility == "efficient"
    assert manual.utility == "laborious"


# CVSS 4.0 safety is S:P or MSI:S / MSA:S, never SC:H


def test_safety_flag_reads_the_right_cvss4_metric() -> None:
    from icsmatch.ingest.enrich import _safety_flag

    assert _safety_flag("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H") is False
    assert _safety_flag("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/S:P") is True
    assert _safety_flag("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MSI:S") is True
    assert _safety_flag("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") is False, "3.x has no safety metric"
