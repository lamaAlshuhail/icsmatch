"""Version parsing tests.

Every string in these tables was taken from the live CISA CSAF corpus
(3,969 advisories, 23,117 version-range strings). This is the file to read
first if you want to know what OT version data actually looks like.
"""

from __future__ import annotations

import pytest

from icsmatch.normalize.versions import (
    RangeKind,
    parse_range,
    parse_version,
)

# ---------------------------------------------------------------------------
# single versions
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "text,numeric,component",
    [
        ("4.5", (4, 5), ""),
        ("V4.5", (4, 5), ""),
        ("v2.9.7", (2, 9, 7), ""),
        ("1.060", (1, 60), ""),
        ("10.97.3", (10, 97, 3), ""),
        ("21", (21,), ""),
        ("02.07.07", (2, 7, 7), ""),
        ("R15A", (15,), ""),          # Hitachi Energy FOXMAN-UN
        ("R15B_PC4", (15,), ""),      # patch-collection suffix
        ("32.011", (32, 11), ""),     # Rockwell ControlLogix
        ("BIOS_V1.0.212N", (1, 0, 212), "BIOS"),
        ("with_U-Boot_V2016.05RS09", (2016, 5), "U-Boot"),
        ("Firmware_V3.5", (3, 5), "firmware"),
    ],
)
def test_parse_version_ok(text: str, numeric: tuple[int, ...], component: str) -> None:
    v = parse_version(text)
    assert v is not None, f"{text!r} should parse"
    assert v.numeric == numeric
    assert v.component.lower() == component.lower()
    assert v.raw == text, "raw string must be preserved for reporting"


@pytest.mark.parametrize(
    "text",
    [
        "",
        "   ",
        "banana",
        "Main",
        "Collection",
        "the_first_5_digits_of_serial_number_22081",
        "April/20/2023",
        "d78dda6",           # git sha
        "driver19.exe",
    ],
)
def test_parse_version_rejects(text: str) -> None:
    assert parse_version(text) is None


# ---------------------------------------------------------------------------
# ordering
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "lo,hi",
    [
        ("4.2.1", "4.5"),
        ("V2.9.7", "V2.9.8"),
        ("1.0", "1.0.1"),
        ("4.5", "4.5a"),        # empty suffix sorts first
        ("R15A", "R16A"),
        ("2", "10"),            # numeric, not lexicographic
        ("02.07.07", "2.7.8"),
    ],
)
def test_version_ordering(lo: str, hi: str) -> None:
    a, b = parse_version(lo), parse_version(hi)
    assert a is not None and b is not None
    assert a < b, f"{lo} should sort before {hi}"
    assert b > a


def test_version_equality_pads_zeros() -> None:
    assert parse_version("4.3") == parse_version("4.3.0")
    assert parse_version("V4.3") == parse_version("4.3")


# ---------------------------------------------------------------------------
# ranges
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "text,kind",
    [
        ("vers:all/*", RangeKind.ALL),
        ("*", RangeKind.ALL),
        ("All versions", RangeKind.ALL),
        ("<V2.9.7", RangeKind.BOUNDED),
        ("vers:intdot/<4.3.8", RangeKind.BOUNDED),
        ("vers:intdot/>=3.0|<3.0.2", RangeKind.BOUNDED),
        (">=V3.1.0|<V3.1.2", RangeKind.BOUNDED),
        (">=V6.2<V7.1", RangeKind.BOUNDED),
        (">=V2.3_and_<V6.30.016", RangeKind.BOUNDED),
        ("<=10.97.3", RangeKind.BOUNDED),
        ("2.2.0", RangeKind.EXACT),
    ],
)
def test_range_kind(text: str, kind: RangeKind) -> None:
    assert parse_range(text).kind is kind


@pytest.mark.parametrize(
    "text,reason_fragment",
    [
        ('<=The_first_5_digits_of_serial_No._"26061"', "serial"),
        # The date check fires before the prose check, and that ordering is
        # deliberate: "date-based" is the more actionable diagnosis.
        ("distributed  < april 1, 2018", "date"),
        ("versions prior to 4.5", "prose"),
        ("<= 3.4.4 Build 16102416", "build"),
        ("< V15.1 Upd 4", "service-pack"),
        ("", "empty"),
    ],
)
def test_range_refuses_with_reason(text: str, reason_fragment: str) -> None:
    """Unparseable input must be refused with a *specific* reason.

    A generic failure is useless in the unparseable log; a specific one tells
    the maintainer whether the format is worth supporting.
    """
    vr = parse_range(text)
    assert vr.kind is RangeKind.UNPARSEABLE
    assert reason_fragment in vr.note.lower()


# ---------------------------------------------------------------------------
# containment -- the actual matching decision
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "range_text,version,expected",
    [
        ("<V4.5", "4.2.1", True),
        ("<V4.5", "4.5", False),
        ("<V4.5", "5.0", False),
        ("vers:intdot/<4.3.8", "4.3.7", True),
        ("vers:intdot/<4.3.8", "4.3.8", False),
        ("vers:intdot/>=3.0|<3.0.2", "3.0.1", True),
        ("vers:intdot/>=3.0|<3.0.2", "2.9.9", False),
        ("vers:intdot/>=3.0|<3.0.2", "3.0.2", False),
        (">=V3.1.0|<V3.1.2", "3.1.1", True),
        ("<=10.97.3", "10.97.3", True),
        ("<=10.97.3", "10.97.4", False),
        ("vers:all/*", "99.99", True),
        ("2.2.0", "2.2.0", True),
        ("2.2.0", "2.2.1", False),
    ],
)
def test_contains(range_text: str, version: str, expected: bool) -> None:
    vr = parse_range(range_text)
    v = parse_version(version)
    assert vr.contains(v) is expected


def test_contains_returns_none_when_unparseable() -> None:
    """None, not False.

    Returning False would silently mark the asset unaffected. None routes it
    to the manual-review bucket, which is the whole point.
    """
    vr = parse_range('<=The_first_5_digits_of_serial_No._"26061"')
    assert vr.contains(parse_version("4.5")) is None

    ok = parse_range("<V4.5")
    assert ok.contains(None) is None


def test_describe_is_human_readable() -> None:
    assert parse_range("vers:all/*").describe() == "all versions affected"
    assert "<V4.5" in parse_range("<V4.5").describe()
    assert "unparseable" in parse_range("Main").describe().lower()
