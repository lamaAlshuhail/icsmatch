"""vendor and product name canonicalisation.

an advisory says "Siemens AG / SIMATIC S7-1200 CPU family", the inventory says
"Siemens,S7-1200". same device, no string equality.

a product name is reduced to two parts, not one:

    brand  the vendor's marketing line (SIMATIC, SICAM, MicroLogix)
    core   what is left once the brand and descriptive noise are removed

both parts are kept. collapsing to the core alone is what makes "SIPROTEC 5"
and "SICAM 5" look identical, since both reduce to "5". the matcher requires
brand agreement whenever both sides declare one, and treats a short or
all-numeric core as low entropy that cannot carry a match on its own.

alias tables live in data/normalizers.yaml. the tables below are the fallback
used when PyYAML is absent.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

__all__ = [
    "ProductKey",
    "canon_vendor",
    "canon_product",
    "product_key",
    "keys_agree",
    "is_low_entropy",
    "load_aliases",
    "fuzzy_ratio",
    "fuzzy_batch",
    "HAVE_RAPIDFUZZ",
]


_VENDOR_ALIASES: dict[str, list[str]] = {
    "siemens": ["siemens ag", "siemens energy", "siemens healthineers", "siemens mobility",
                "siemens digital industries"],
    "schneider": ["schneider electric", "schneider-electric", "modicon", "apc by schneider",
                  "apc by schneider electric", "telemecanique"],
    "rockwell": ["rockwell automation", "allen-bradley", "allen bradley", "ab"],
    "hitachienergy": ["hitachi energy", "hitachi abb power grids", "abb power grids"],
    "abb": ["abb ltd", "abb inc"],
    "honeywell": ["honeywell international", "honeywell process solutions",
                  "honeywell building technologies"],
    "emerson": ["emerson electric", "emerson process management", "fisher",
                "fisher-rosemount"],
    "yokogawa": ["yokogawa electric", "yokogawa electric corporation"],
    "mitsubishi": ["mitsubishi electric", "mitsubishi electric corporation"],
    "ge": ["general electric", "ge digital", "ge grid solutions", "ge healthcare",
           "ge vernova", "ge gas power", "ge power"],
    "omron": ["omron corporation"],
    "phoenixcontact": ["phoenix contact"],
    "wago": ["wago kontakttechnik"],
    "moxa": ["moxa inc"],
    "advantech": ["advantech co"],
    "delta": ["delta electronics"],
}

# "software" belongs here, not in _TRAILING_NOISE: otherwise
# "Schneider Electric Software, LLC" and "Schneider Electric" split in two.
_CORP_SUFFIX = re.compile(
    r"\b(?:ag|inc|corp|corporation|co|ltd|limited|gmbh|llc|plc|s\.?a\.?|b\.?v\.?|"
    r"kg|kgaa|group|holdings?|international|electric|electronics|"
    r"software|systems|solutions|technologies|automation|industries)\b\.?",
    re.I,
)

# family prefixes that come before a model. kept as a separate field so a
# brand disagreement can veto a match, never silently discarded.
_BRANDS = (
    "simatic", "simotion", "sinamics", "sinema", "sinec", "scalance",
    "siprotec", "sicam", "sentron", "desigo", "ruggedcom", "siplus",
    "controllogix", "compactlogix", "micrologix", "guardlogix", "flexlogix",
    "softlogix", "factorytalk", "panelview",
    "modicon", "ecostruxure", "powerlogic", "easergy", "harmony", "vijeo",
    "altivar", "powerchute",
    "proficy", "cimplicity",
    "experion", "controledge",
    "deltav", "ovation",
    "centum", "prosafe", "stardom",
    "melsec", "melsoft", "melipc",
)
# variant lines that advisories fold into the parent line, usually with a
# scope note such as "(incl. SIPLUS variants)". the scope note is dropped
# during normalisation, so the family has to be known here instead.
_BRAND_FAMILY = {
    "siplus": "simatic",
}

_BRAND_PREFIX = re.compile(r"^\s*(?:" + "|".join(_BRANDS) + r")\b[\s._-]*", re.I)

# tokens that add no identity. "software" is not here: an "S7-1500 Software
# Controller" is a different product from an "S7-1500 CPU".
_TRAILING_NOISE = re.compile(
    r"\b(?:cpu|plc|hmi|rtu|series|family|line|products?|devices?|modules?|"
    r"controllers?|firmware|platform|systems?|all\s+versions?)\b",
    re.I,
)

_NON_ALNUM = re.compile(r"[^a-z0-9]+")

# a trailing parenthetical of one token is an order number and is identity.
# a multi-word one is a scope note and is dropped.
_SCOPE_NOTE = re.compile(r"\(\s*[^()]*\s+[^()]*\)\s*$")

# fold a trailing s so "Comfort Panels" meets "Comfort Panel", leaving
# -ss, -us and -is alone so SIPLUS and Access survive.
_PLURAL = re.compile(r"\b([A-Za-z]{3,}?[^sui])s\b")

# a core this short, or all digits, cannot identify a product alone:
# "5" is shared by SIPROTEC 5 and SICAM 5, "1400" by MicroLogix and ControlLogix.
MIN_CORE_LEN = 4


@dataclass(frozen=True)
class ProductKey:
    """canonical product identity: a brand line plus a core token."""

    __slots__ = ("brand", "core", "raw")

    brand: str
    core: str
    raw: str

    @property
    def full(self) -> str:
        return f"{self.brand}{self.core}"

    @property
    def low_entropy(self) -> bool:
        return is_low_entropy(self.core)

    def __bool__(self) -> bool:
        return bool(self.core or self.brand)

    def __str__(self) -> str:
        return self.full


def is_low_entropy(core: str) -> bool:
    """true when a core is too short or too generic to stand alone."""
    if not core:
        return True
    return len(core) < MIN_CORE_LEN or core.isdigit()


def load_aliases(path: Path | str | None = None) -> dict[str, Any]:
    """load normalizers.yaml over the built-in tables, if it is readable."""
    if path is None:
        path = Path(__file__).resolve().parents[3] / "data" / "normalizers.yaml"
    path = Path(path)
    if not path.exists():
        return {"vendor_aliases": _VENDOR_ALIASES}
    try:
        import yaml  # type: ignore
    except ImportError:
        return {"vendor_aliases": _VENDOR_ALIASES}
    try:
        with path.open(encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except Exception:
        return {"vendor_aliases": _VENDOR_ALIASES}

    merged = dict(_VENDOR_ALIASES)
    for canon, aliases in (data.get("vendor_aliases") or {}).items():
        merged.setdefault(canon, [])
        merged[canon] = list({*merged[canon], *(aliases or [])})
    return {"vendor_aliases": merged}


@lru_cache(maxsize=1)
def _alias_lookup() -> dict[str, str]:
    table = load_aliases()["vendor_aliases"]
    lookup: dict[str, str] = {}
    for canon, aliases in table.items():
        lookup[_squash(canon)] = canon
        for a in aliases:
            lookup[_squash(a)] = canon
    return lookup


def _squash(text: str) -> str:
    return _NON_ALNUM.sub("", text.lower())


@lru_cache(maxsize=4096)
def canon_vendor(name: str) -> str:
    """canonical vendor key.

    >>> canon_vendor("Siemens AG")
    'siemens'
    >>> canon_vendor("Allen-Bradley")
    'rockwell'
    """
    if not name:
        return ""
    raw = name.strip().lower()

    direct = _alias_lookup().get(_squash(raw))
    if direct:
        return direct

    stripped = _CORP_SUFFIX.sub(" ", raw)
    key = _squash(stripped)
    return _alias_lookup().get(key, key or _squash(raw))


@lru_cache(maxsize=8192)
def product_key(name: str, vendor: str = "") -> ProductKey:
    """split a product name into brand and core.

    when vendor is supplied, a vendor name repeated at the front of the
    product name is dropped: advisories write "Allen-Bradley MicroLogix 1400"
    where an inventory writes "MicroLogix 1400".

    >>> product_key("SIMATIC S7-1200 CPU family")
    ProductKey(brand='simatic', core='s71200', raw='SIMATIC S7-1200 CPU family')
    >>> product_key("SIPROTEC 5").core
    '5'
    >>> product_key("SICAM 5").brand
    'sicam'
    """
    if not name:
        return ProductKey("", "", "")

    working = _SCOPE_NOTE.sub("", name.strip()).strip()
    if vendor:
        working = _drop_vendor_prefix(working, canon_vendor(vendor))
    brands: list[str] = []
    for _ in range(3):
        m = _BRAND_PREFIX.match(working)
        if not m:
            break
        brands.append(_squash(m.group(0)))
        working = working[m.end():]

    working = _TRAILING_NOISE.sub(" ", working)
    working = _PLURAL.sub(r"\1", working)
    core = _NON_ALNUM.sub("", working.lower())
    brand = brands[0] if brands else ""

    if not core and brand:
        return ProductKey(brand, brand, name.strip())
    return ProductKey(brand, core, name.strip())


def _drop_vendor_prefix(name: str, vendor_key: str) -> str:
    """remove a leading vendor mention from a product name."""
    if not vendor_key:
        return name
    words = name.split()
    for take in (3, 2, 1):
        if len(words) <= take:
            continue
        if canon_vendor(" ".join(words[:take])) == vendor_key:
            return " ".join(words[take:])
    return name


def canon_product(name: str, vendor: str = "") -> str:
    """core token only. kept for callers that want a single string."""
    return product_key(name, vendor).core


def keys_agree(a: ProductKey, b: ProductKey) -> str | None:
    """decide whether two product keys name the same product.

    returns "exact" for a confident identity, "weak" when the cores line up but
    nothing discriminating backs them, and None for disagreement.

    >>> keys_agree(product_key("SIPROTEC 5"), product_key("SICAM 5")) is None
    True
    >>> keys_agree(product_key("S7-1200"), product_key("SIMATIC S7-1200"))
    'exact'
    """
    if not a.core or not b.core:
        return None
    if a.core != b.core:
        return None

    # differing brands mean different products unless one is a variant line
    if a.brand and b.brand and a.brand != b.brand:
        fam_a = _BRAND_FAMILY.get(a.brand, a.brand)
        fam_b = _BRAND_FAMILY.get(b.brand, b.brand)
        if fam_a != fam_b:
            return None

    if a.low_entropy and not (a.brand and b.brand):
        return "weak"
    return "exact"


HAVE_RAPIDFUZZ = False
try:  # pragma: no cover - depends on the install
    from rapidfuzz import fuzz as _rf_fuzz
    from rapidfuzz import process as _rf_process

    HAVE_RAPIDFUZZ = True
except ImportError:  # pragma: no cover
    _rf_fuzz = None  # type: ignore[assignment]
    _rf_process = None  # type: ignore[assignment]


def fuzzy_ratio(a: str, b: str) -> float:
    """token-set similarity in [0, 1]."""
    if not a or not b:
        return 0.0
    if HAVE_RAPIDFUZZ:
        return float(_rf_fuzz.token_set_ratio(a, b)) / 100.0
    from difflib import SequenceMatcher

    return SequenceMatcher(None, a, b).ratio()


def fuzzy_batch(query: str, choices: list[str], cutoff: float) -> list[tuple[int, float]]:
    """score one string against many, returning (index, ratio) above cutoff.

    uses rapidfuzz process.extract when available, which drops into C++ and
    filters on the cutoff there. process.cdist would also work but pulls in
    numpy, which rapidfuzz does not install, so a plain `pip install
    rapidfuzz` would break at runtime. falls back to difflib with a cheap
    length prefilter.
    """
    if not query or not choices:
        return []

    if HAVE_RAPIDFUZZ:
        hits = _rf_process.extract(
            query,
            choices,
            scorer=_rf_fuzz.token_set_ratio,
            score_cutoff=cutoff * 100.0,
            limit=None,
        )
        return [(idx, float(score) / 100.0) for _, score, idx in hits]

    from difflib import SequenceMatcher

    out: list[tuple[int, float]] = []
    qlen = len(query)
    matcher = SequenceMatcher()
    matcher.set_seq2(query)
    for i, choice in enumerate(choices):
        # ratio is bounded by 2*min/(len_a+len_b); skip what cannot clear cutoff
        if not choice:
            continue
        if 2.0 * min(qlen, len(choice)) / (qlen + len(choice)) < cutoff:
            continue
        matcher.set_seq1(choice)
        if matcher.real_quick_ratio() < cutoff or matcher.quick_ratio() < cutoff:
            continue
        r = matcher.ratio()
        if r >= cutoff:
            out.append((i, r))
    return out
