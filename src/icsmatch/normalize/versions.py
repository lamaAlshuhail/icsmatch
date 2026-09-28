"""version and version-range parsing for OT advisories.

packaging.version cannot parse real OT firmware versions. a pass over every
version-range string in CISA's CSAF corpus turns up:

    bounded comparator   <V2.9.7   >=1.060   vers:intdot/>=3.0|<3.0.2
    all versions         vers:all/*
    exact pin            R15B_PC4
    unparseable tail     see below

the unparseable tail:

    <=The_first_5_digits_of_serial_No._"26061"
    distributed  < april 1, 2018
    <= 3.4.4 Build 16102416
    < V15.1 Upd 4
    >=V2.3_and_<V6.30.016

this parser returns UNPARSEABLE rather than guessing, and every failure keeps
its reason, so the failures stay countable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

__all__ = [
    "Version",
    "Comparator",
    "VersionRange",
    "RangeKind",
    "parse_version",
    "parse_range",
]


_VERSION_PREFIX = re.compile(r"^(?:versions?|rev(?:ision)?|fw|sw|hw|[vr])[\s._-]*", re.I)

# a component qualifier scopes the version to a sub-component, as in
# <BIOS_V1.0.212N or <firmware_SP473. "BIOS < 1.0" and "firmware < 1.0" are
# different claims, so the component travels with the version.
_COMPONENT_QUALIFIER = re.compile(
    r"""
    ^
    (?:with[\s_]+)?                       # optional "with_"
    (?P<component>
        BIOS | firmware | U-Boot | bootloader | HMI | SW | ROS | ROX | HiOS
    )
    [\s._-]+
    (?P<rest>.+)
    $
    """,
    re.X | re.I,
)

_VERSION_CORE = re.compile(
    r"""
    ^
    (?P<numeric>\d+(?:[._]\d+)*)        # 4  |  4.5  |  4.3.8  |  02.07.07
    (?P<suffix>[A-Za-z0-9._+\-()]*)     # a  |  _PC4 |  (10)   |  E0a
    $
    """,
    re.X,
)


@dataclass(frozen=True, order=False)
class Version:
    """a comparable OT version.

    numeric segments compare first, zero-padded so 4.3 and 4.3.0 are equal,
    then a case-folded comparison of the suffix. raw is always preserved so
    reports echo what the advisory said.
    """

    raw: str
    numeric: tuple[int, ...]
    suffix: str = ""
    component: str = ""  # "BIOS", "firmware", ... "" means the product itself

    def _key(self, width: int) -> tuple:
        padded = self.numeric + (0,) * (width - len(self.numeric))
        return padded

    def _cmp(self, other: Version) -> int:
        width = max(len(self.numeric), len(other.numeric))
        a, b = self._key(width), other._key(width)
        if a != b:
            return -1 if a < b else 1
        # numeric parts equal, compare suffix. empty sorts first: 4.5 < 4.5a
        sa, sb = self.suffix.lower(), other.suffix.lower()
        if sa == sb:
            return 0
        if not sa:
            return -1
        if not sb:
            return 1
        return -1 if sa < sb else 1

    def __lt__(self, other: Version) -> bool:
        return self._cmp(other) < 0

    def __le__(self, other: Version) -> bool:
        return self._cmp(other) <= 0

    def __gt__(self, other: Version) -> bool:
        return self._cmp(other) > 0

    def __ge__(self, other: Version) -> bool:
        return self._cmp(other) >= 0

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        return self._cmp(other) == 0

    def __hash__(self) -> int:
        return hash((self.numeric, self.suffix.lower(), self.component.lower()))

    def __str__(self) -> str:
        return self.raw


def parse_version(text: str) -> Version | None:
    """parse a single version string. returns None if unparseable.

    >>> parse_version("V4.5").numeric
    (4, 5)
    >>> parse_version("R15B_PC4").numeric
    (15,)
    >>> parse_version("banana") is None
    True
    """
    if not text:
        return None
    raw = text.strip()
    if not raw:
        return None

    component = ""
    qual = _COMPONENT_QUALIFIER.match(raw)
    if qual:
        component = qual.group("component")
        working = qual.group("rest").strip()
    else:
        working = raw

    cleaned = _VERSION_PREFIX.sub("", working).strip()
    # underscore behaves as a dot only between digits: 02_07 -> 02.07
    cleaned = re.sub(r"(?<=\d)_(?=\d)", ".", cleaned)

    m = _VERSION_CORE.match(cleaned)
    if not m:
        return None

    numeric_txt = m.group("numeric").replace("_", ".")
    try:
        numeric = tuple(int(p) for p in numeric_txt.split(".") if p != "")
    except ValueError:
        return None
    if not numeric:
        return None

    return Version(
        raw=raw,
        numeric=numeric,
        suffix=m.group("suffix") or "",
        component=component,
    )


class Comparator(str, Enum):
    LT = "<"
    LTE = "<="
    GT = ">"
    GTE = ">="
    EQ = "="


class RangeKind(str, Enum):
    ALL = "ALL"
    BOUNDED = "BOUNDED"
    EXACT = "EXACT"
    UNPARSEABLE = "UNPARSEABLE"


@dataclass
class _Constraint:
    op: Comparator
    version: Version

    def satisfied_by(self, v: Version) -> bool:
        if self.op is Comparator.LT:
            return v < self.version
        if self.op is Comparator.LTE:
            return v <= self.version
        if self.op is Comparator.GT:
            return v > self.version
        if self.op is Comparator.GTE:
            return v >= self.version
        return v == self.version

    def __str__(self) -> str:
        return f"{self.op.value}{self.version.raw}"


@dataclass
class VersionRange:
    """a parsed version range with an explicit kind.

    contains() returns None, not False, when the range could not be parsed, so
    callers route to review instead of silently treating an asset as safe.
    """

    raw: str
    kind: RangeKind
    constraints: list[_Constraint] = field(default_factory=list)
    note: str = ""

    def contains(self, v: Version | None) -> bool | None:
        if self.kind is RangeKind.UNPARSEABLE:
            return None
        if self.kind is RangeKind.ALL:
            return True
        if v is None:
            return None
        return all(c.satisfied_by(v) for c in self.constraints)

    def describe(self) -> str:
        """basis string, used verbatim in reports."""
        if self.kind is RangeKind.ALL:
            return "all versions affected"
        if self.kind is RangeKind.UNPARSEABLE:
            return f"unparseable range {self.raw!r}"
        return " and ".join(str(c) for c in self.constraints)

    @property
    def parseable(self) -> bool:
        return self.kind is not RangeKind.UNPARSEABLE

    @property
    def component(self) -> str:
        """sub-component this range is scoped to, or empty for the product."""
        for c in self.constraints:
            if c.version.component:
                return c.version.component
        return ""



_ALL_TOKENS = {"vers:all/*", "*", "<*", "all", "all versions"}

_CONSTRAINT = re.compile(r"(?P<op><=|>=|<|>|=)\s*(?P<ver>[^<>=|,\s]+)")

# refused on purpose. matching early keeps the failure reason specific.
_REFUSE = [
    (re.compile(r"serial[\s_]*no", re.I), "serial-number constraint, not a version"),
    (
        re.compile(r"\b(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)\w*\s+\d", re.I),
        "date-based constraint, not a version",
    ),
    (re.compile(r"\bbuild\b", re.I), "build-qualified version"),
    (re.compile(r"\bupd\b|\bsp\d", re.I), "service-pack / update qualifier"),
]


def _strip_vers_scheme(text: str) -> str:
    """vers:intdot/<4.3.8 -> <4.3.8

    the vers URI scheme puts the versioning system between the scheme and the
    constraints. we keep the constraints and drop the system name; intdot is
    dotted-integer, which is what the comparator already assumes.
    """
    if not text.startswith("vers:"):
        return text
    _, _, rest = text.partition("/")
    return rest or text


def parse_range(text: str) -> VersionRange:
    """parse a CSAF product_version_range string.

    >>> parse_range("vers:all/*").kind
    <RangeKind.ALL: 'ALL'>
    >>> parse_range("<V4.5").describe()
    '<V4.5'
    >>> parse_range("vers:intdot/>=3.0|<3.0.2").kind
    <RangeKind.BOUNDED: 'BOUNDED'>
    >>> parse_range('<=The_first_5_digits_of_serial_No._"26061"').kind
    <RangeKind.UNPARSEABLE: 'UNPARSEABLE'>
    """
    raw = (text or "").strip()
    if not raw:
        return VersionRange(raw=raw, kind=RangeKind.UNPARSEABLE, note="empty")

    lowered = raw.lower()

    if lowered in _ALL_TOKENS or lowered.startswith("all version"):
        return VersionRange(raw=raw, kind=RangeKind.ALL)

    # refusals carry a specific reason
    for pattern, reason in _REFUSE:
        if pattern.search(raw):
            return VersionRange(raw=raw, kind=RangeKind.UNPARSEABLE, note=reason)

    if re.search(r"prior to|before|earlier than|older than|distributed", raw, re.I):
        return VersionRange(
            raw=raw, kind=RangeKind.UNPARSEABLE, note="prose range, no machine syntax"
        )

    body = _strip_vers_scheme(raw)
    # _and_ is a Siemens-ism: >=V2.3_and_<V6.30.016
    body = re.sub(r"_and_", "|", body, flags=re.I)

    constraints: list[_Constraint] = []
    for m in _CONSTRAINT.finditer(body):
        v = parse_version(m.group("ver"))
        if v is None:
            return VersionRange(
                raw=raw,
                kind=RangeKind.UNPARSEABLE,
                note=f"unparseable version token {m.group('ver')!r}",
            )
        constraints.append(_Constraint(op=Comparator(m.group("op")), version=v))

    if constraints:
        return VersionRange(raw=raw, kind=RangeKind.BOUNDED, constraints=constraints)

    v = parse_version(body)
    if v is not None:
        return VersionRange(
            raw=raw,
            kind=RangeKind.EXACT,
            constraints=[_Constraint(op=Comparator.EQ, version=v)],
        )

    return VersionRange(raw=raw, kind=RangeKind.UNPARSEABLE, note="no recognisable constraint")
