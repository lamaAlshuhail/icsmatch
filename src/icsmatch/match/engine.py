"""asset inventory x advisory corpus -> verdicts.

every match carries a tier, a confidence and a basis string, so an analyst
can audit it without opening the source JSON. tiers above 3 are surfaced for
review rather than asserted.

tier cascade, first hit wins:

    0  analyst-confirmed alias            1.00  AFFECTED
    1  model / SKU exact                  1.00  AFFECTED
    2  CPE exact                          0.95  AFFECTED
    3  vendor + product + version in range 0.85  AFFECTED
    4  vendor + fuzzy product             ~0.60  REVIEW
    5  vendor only                         0.30  MANUAL

tier 0 outranks an exact SKU match because a human looked at it. analyst
decisions suppress as well as promote.

SKU outranks CPE because the data says so: across the CISA CSAF corpus only
about 0.1% of products carry a CPE while about 29% carry a model number.

matching runs against a prebuilt index rather than a full scan. each asset
looks up a handful of candidate buckets instead of touching every product in
the corpus.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from enum import Enum, IntEnum

from ..ingest.csaf import Advisory, CSAFProduct, ProductStatus
from ..normalize.product import (
    ProductKey,
    canon_vendor,
    fuzzy_batch,
    keys_agree,
    product_key,
)
from ..normalize.versions import Version, parse_version
from ..store.decisions import Decision, LearnedAlias

__all__ = [
    "Asset",
    "Match",
    "Verdict",
    "Tier",
    "CorpusIndex",
    "match_assets",
    "FUZZY_THRESHOLD",
]


FUZZY_THRESHOLD = 0.82


class Tier(IntEnum):
    ALIAS = 0
    SKU = 1
    CPE = 2
    EXACT = 3
    FUZZY = 4
    VENDOR = 5


class Verdict(str, Enum):
    AFFECTED = "AFFECTED"
    REVIEW = "REVIEW"
    MANUAL = "MANUAL"
    UNKNOWN = "UNKNOWN"
    NOT_AFFECTED = "NOT_AFFECTED"


_TIER_META: dict[Tier, tuple[float, Verdict]] = {
    Tier.ALIAS: (1.00, Verdict.AFFECTED),
    Tier.SKU: (1.00, Verdict.AFFECTED),
    Tier.CPE: (0.95, Verdict.AFFECTED),
    Tier.EXACT: (0.85, Verdict.AFFECTED),
    Tier.FUZZY: (0.60, Verdict.REVIEW),
    Tier.VENDOR: (0.30, Verdict.MANUAL),
}


def _norm_ident(text: str) -> str:
    return "".join(ch for ch in text.lower() if ch.isalnum())


@dataclass
class Asset:
    """one row of an asset inventory."""

    asset_id: str
    vendor: str
    product: str
    version: str = ""
    model: str = ""
    cpe: str = ""
    purdue_level: str = ""
    site: str = ""

    vendor_key: str = field(init=False, default="")
    key: ProductKey = field(init=False, repr=False, default=None)  # type: ignore[assignment]
    parsed_version: Version | None = field(init=False, default=None)
    model_key: str = field(init=False, default="")
    cpe_key: str = field(init=False, default="")

    def __post_init__(self) -> None:
        self.vendor_key = canon_vendor(self.vendor)
        self.key = product_key(self.product, self.vendor)
        self.parsed_version = parse_version(self.version) if self.version else None
        self.model_key = _norm_ident(self.model) if self.model else ""
        self.cpe_key = ":".join(self.cpe.lower().split(":")[:5]) if self.cpe else ""

    @property
    def product_key(self) -> str:
        return self.key.full

    @classmethod
    def from_row(cls, row: dict[str, str]) -> Asset:
        """build from a CSV row, tolerating common header spellings."""

        def pick(*names: str, default: str = "") -> str:
            for n in names:
                for k, v in row.items():
                    if k and k.strip().lower().replace(" ", "_") == n:
                        return (v or "").strip()
            return default

        return cls(
            asset_id=pick("asset_id", "id", "tag", "hostname", default="?"),
            vendor=pick("vendor", "manufacturer", "make"),
            product=pick("product", "model_name", "device", "product_name"),
            version=pick("version", "firmware", "firmware_version", "fw"),
            model=pick("model", "model_number", "order_number", "part_number", "sku"),
            cpe=pick("cpe"),
            purdue_level=pick("purdue_level", "purdue", "level", "zone"),
            site=pick("site", "location", "plant", "facility"),
        )

    @property
    def recognised(self) -> bool:
        """true when the row carried at least one matchable field."""
        return bool(self.vendor_key or self.model_key or self.key.core)


@dataclass
class Match:
    asset: Asset
    advisory: Advisory
    product: CSAFProduct
    tier: Tier
    confidence: float
    verdict: Verdict
    basis: str

    @property
    def cves(self) -> list[str]:
        """CVEs from this advisory that name this product."""
        pid = self.product.product_id
        hits = [v.cve for v in self.advisory.vulns if pid in v.known_affected and v.cve]
        return hits or self.advisory.cves

    @property
    def cvss(self) -> float | None:
        return self._worst[0]

    @property
    def cvss_vector(self) -> str:
        return self._worst[1]

    @property
    def _worst(self) -> tuple[float | None, str]:
        """highest scoring vulnerability that names this product."""
        pid = self.product.product_id
        best: tuple[float | None, str] = (None, "")
        for v in self.advisory.vulns:
            if v.cvss_score is None:
                continue
            if pid not in v.known_affected:
                continue
            if best[0] is None or v.cvss_score > best[0]:
                best = (v.cvss_score, v.cvss_vector)
        if best[0] is not None:
            return best
        for v in self.advisory.vulns:
            if v.cvss_score is not None and (best[0] is None or v.cvss_score > best[0]):
                best = (v.cvss_score, v.cvss_vector)
        return best


@dataclass(frozen=True)
class _Leaf:
    """one advisory product, kept with its advisory for candidate lookup."""

    __slots__ = ("advisory", "product")

    advisory: Advisory
    product: CSAFProduct


class CorpusIndex:
    """inverted indexes over the advisory corpus.

    built once per run. the cost is one pass over the products; every asset
    then does dict lookups instead of a full scan.
    """

    def __init__(self, advisories: Iterable[Advisory]) -> None:
        self.by_ident: dict[str, list[_Leaf]] = {}
        self.by_cpe: dict[str, list[_Leaf]] = {}
        self.by_core: dict[tuple[str, str], list[_Leaf]] = {}
        self.by_full: dict[tuple[str, str], list[_Leaf]] = {}
        self.by_vendor: dict[str, list[_Leaf]] = {}
        self.vendor_keys: dict[str, list[ProductKey]] = {}
        self.advisory_count = 0
        self.product_count = 0

        seen_keys: dict[str, set[str]] = {}
        for advisory in advisories:
            self.advisory_count += 1
            for prod in advisory.products:
                self.product_count += 1
                leaf = _Leaf(advisory, prod)

                for ident in (*prod.skus, *prod.model_numbers):
                    norm = _norm_ident(ident)
                    if norm:
                        self.by_ident.setdefault(norm, []).append(leaf)

                if prod.cpe:
                    self.by_cpe.setdefault(
                        ":".join(prod.cpe.lower().split(":")[:5]), []
                    ).append(leaf)

                vk = prod.vendor_key
                if not vk:
                    continue
                self.by_vendor.setdefault(vk, []).append(leaf)

                core = prod.key.core
                if not core:
                    continue
                self.by_core.setdefault((vk, core), []).append(leaf)
                self.by_full.setdefault((vk, prod.key.full), []).append(leaf)

                bucket = seen_keys.setdefault(vk, set())
                if prod.key.full not in bucket:
                    bucket.add(prod.key.full)
                    self.vendor_keys.setdefault(vk, []).append(prod.key)

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"CorpusIndex(advisories={self.advisory_count}, "
            f"products={self.product_count}, vendors={len(self.by_vendor)})"
        )


def _version_clause(asset: Asset, prod: CSAFProduct) -> tuple[bool | None, str]:
    """evaluate the version predicate, returning (in_range, description)."""
    vr = prod.version_range
    if not vr.parseable:
        return None, f"version range {vr.raw!r} unparseable ({vr.note})"

    # a range scoped to a sub-component says nothing about the version column
    # the inventory actually tracks.
    comp = vr.component
    if comp and (asset.parsed_version is None or asset.parsed_version.component.lower() != comp.lower()):
        return None, f"range applies to {comp}, inventory version is not scoped to it"

    result = vr.contains(asset.parsed_version)
    if result is None:
        if asset.parsed_version is None:
            return None, f"asset version {asset.version or '(blank)'!r} unparseable"
        return None, f"version range {vr.raw!r} indeterminate"
    return result, vr.describe()


def _status_gate(advisory: Advisory, product_id: str) -> tuple[bool, str]:
    """apply CSAF product_status before asserting a finding.

    returns (keep, note). only known_affected and the affected range endpoints
    justify a finding. known_not_affected and fixed suppress it, and
    under_investigation downgrades it to a watch.
    """
    statuses = advisory.status_of(product_id)
    if not statuses:
        return True, ""
    if ProductStatus.KNOWN_AFFECTED in statuses:
        return True, ""
    if ProductStatus.FIRST_AFFECTED in statuses or ProductStatus.LAST_AFFECTED in statuses:
        return True, ""
    if ProductStatus.UNDER_INVESTIGATION in statuses:
        return True, "vendor lists this product as under investigation"
    if ProductStatus.KNOWN_NOT_AFFECTED in statuses:
        return False, "vendor states not affected"
    if ProductStatus.FIXED in statuses or ProductStatus.FIRST_FIXED in statuses:
        return False, "vendor lists this product version as fixed"
    return True, ""


def _mk(
    asset: Asset,
    leaf: _Leaf,
    tier: Tier,
    basis: str,
    verdict: Verdict | None = None,
    confidence: float | None = None,
) -> Match | None:
    keep, note = _status_gate(leaf.advisory, leaf.product.product_id)
    default_conf, default_verdict = _TIER_META[tier]
    if not keep:
        # kept, not dropped, so VEX can state it. reports filter it out.
        return Match(
            asset=asset,
            advisory=leaf.advisory,
            product=leaf.product,
            tier=tier,
            confidence=default_conf,
            verdict=Verdict.NOT_AFFECTED,
            basis=f"{basis}; {note}" if note else basis,
        )
    if note:
        basis = f"{basis}; {note}"
        verdict = Verdict.UNKNOWN if verdict is None else verdict
    return Match(
        asset=asset,
        advisory=leaf.advisory,
        product=leaf.product,
        tier=tier,
        confidence=default_conf if confidence is None else confidence,
        verdict=default_verdict if verdict is None else verdict,
        basis=basis,
    )


def _alias_hit(
    asset: Asset,
    leaf: _Leaf,
    aliases: dict[tuple[str, str, str], LearnedAlias],
) -> tuple[str, Match | None] | None:
    """resolve an analyst decision for this pair, if one exists."""
    learned = aliases.get((asset.vendor_key, asset.product_key, leaf.product.product_key))
    if learned is None:
        return None
    if learned.decision is Decision.REJECTED:
        # kept, not dropped, so VEX can state it. reports filter it out.
        return (
            "match",
            Match(
                asset=asset,
                advisory=leaf.advisory,
                product=leaf.product,
                tier=Tier.ALIAS,
                confidence=1.0,
                verdict=Verdict.NOT_AFFECTED,
                basis=learned.basis,
            ),
        )
    if learned.decision is not Decision.CONFIRMED:
        return None

    in_range, ver_desc = _version_clause(asset, leaf.product)
    if in_range is False:
        return ("suppress", None)
    note = ver_desc if in_range is True else f"{ver_desc}; version unconfirmed"
    return (
        "match",
        _mk(
            asset,
            leaf,
            Tier.ALIAS,
            f"{learned.basis}; {note}",
            verdict=Verdict.AFFECTED if in_range else Verdict.UNKNOWN,
        ),
    )


def match_assets(
    assets: Sequence[Asset],
    advisories: Iterable[Advisory] | CorpusIndex,
    *,
    min_tier: Tier = Tier.VENDOR,
    aliases: dict[tuple[str, str, str], LearnedAlias] | None = None,
    fuzzy_threshold: float = FUZZY_THRESHOLD,
    include_not_affected: bool = False,
) -> list[Match]:
    """match every asset against the corpus.

    returns the single best (lowest tier) match per (asset, advisory) pair, so
    a hundred-product advisory does not yield a hundred rows for one asset.

    advisories may be an iterable or a prebuilt CorpusIndex. pass the index
    when matching several inventories against the same corpus.

    vendor-asserted not-affected pairs are dropped unless include_not_affected
    is set, which VEX export uses to state them explicitly.
    """
    index = advisories if isinstance(advisories, CorpusIndex) else CorpusIndex(advisories)
    aliases = aliases or {}

    # confirmed aliases must be reachable even when no tier would have
    # produced the candidate, so index them by the asset side of the pair.
    confirmed: dict[tuple[str, str], list[str]] = {}
    for vendor_key, asset_key, adv_key in aliases:
        confirmed.setdefault((vendor_key, asset_key), []).append(adv_key)

    results: list[Match] = []
    for asset in assets:
        results.extend(
            _match_one(asset, index, aliases, confirmed, min_tier, fuzzy_threshold)
        )
    if not include_not_affected:
        results = [m for m in results if m.verdict is not Verdict.NOT_AFFECTED]
    results.sort(key=lambda m: (m.tier, -(m.cvss or 0.0), m.asset.asset_id))
    return results


class _Collector:
    """keeps the best match per advisory for one asset."""

    __slots__ = ("asset", "aliases", "min_tier", "best", "decided")

    def __init__(
        self,
        asset: Asset,
        aliases: dict[tuple[str, str, str], LearnedAlias],
        min_tier: Tier,
    ) -> None:
        self.asset = asset
        self.aliases = aliases
        self.min_tier = min_tier
        self.best: dict[str, Match] = {}
        self.decided: set[tuple[str, str]] = set()

    def offer(self, m: Match | None) -> None:
        if m is None or m.tier > self.min_tier:
            return
        aid = m.advisory.advisory_id
        cur = self.best.get(aid)
        if cur is None or self._rank(m) < self._rank(cur):
            self.best[aid] = m

    @staticmethod
    def _rank(m: Match) -> tuple[int, int, float]:
        # a not-affected leaf must never displace a real finding for the same
        # advisory: one leaf being clear says nothing about the others.
        return (int(m.verdict is Verdict.NOT_AFFECTED), int(m.tier), -m.confidence)

    def consider(self, leaf: _Leaf, tier: Tier, basis: str, **kw: object) -> None:
        akey = (leaf.advisory.advisory_id, leaf.product.product_id)
        if akey in self.decided:
            return
        if self.aliases:
            decided = _alias_hit(self.asset, leaf, self.aliases)
            if decided is not None:
                self.decided.add(akey)
                if decided[0] == "match":
                    self.offer(decided[1])
                return
        self.offer(_mk(self.asset, leaf, tier, basis, **kw))  # type: ignore[arg-type]


def _match_one(
    asset: Asset,
    index: CorpusIndex,
    aliases: dict[tuple[str, str, str], LearnedAlias],
    confirmed: dict[tuple[str, str], list[str]],
    min_tier: Tier,
    fuzzy_threshold: float,
) -> list[Match]:
    c = _Collector(asset, aliases, min_tier)

    for adv_key in confirmed.get((asset.vendor_key, asset.product_key), ()):
        for leaf in index.by_full.get((asset.vendor_key, adv_key), ()):
            c.consider(leaf, Tier.ALIAS, "analyst-confirmed pair")

    if asset.model_key:
        for leaf in index.by_ident.get(asset.model_key, ()):
            ident = next(
                (
                    i
                    for i in (*leaf.product.skus, *leaf.product.model_numbers)
                    if _norm_ident(i) == asset.model_key
                ),
                asset.model,
            )
            basis = f"model/SKU {asset.model!r} matches advisory identifier {ident!r}"
            # the sku proves identity, not vulnerability. when both sides
            # carry a version, the range still has to hold.
            in_range, ver_desc = _version_clause(asset, leaf.product)
            if in_range is False:
                c.consider(
                    leaf,
                    Tier.SKU,
                    f"{basis}; asset version {asset.version} is outside {ver_desc}",
                    verdict=Verdict.NOT_AFFECTED,
                )
                continue
            if in_range is None and asset.version:
                c.consider(
                    leaf,
                    Tier.SKU,
                    f"{basis}; {ver_desc}",
                    verdict=Verdict.UNKNOWN,
                    confidence=0.7,
                )
                continue
            c.consider(leaf, Tier.SKU, f"{basis}; {ver_desc}" if asset.version else basis)

    if asset.cpe_key:
        for leaf in index.by_cpe.get(asset.cpe_key, ()):
            c.consider(leaf, Tier.CPE, f"CPE {leaf.product.cpe} matches asset CPE")

    vk = asset.vendor_key
    if not vk:
        return list(c.best.values())

    if asset.key.core and min_tier >= Tier.EXACT:
        for leaf in index.by_core.get((vk, asset.key.core), ()):
            agreement = keys_agree(asset.key, leaf.product.key)
            if agreement is None:
                continue
            in_range, ver_desc = _version_clause(asset, leaf.product)
            if in_range is False:
                continue
            if agreement == "weak":
                # the core matched but it is short or all digits and no brand
                # backs it. surface it, do not assert it.
                if min_tier >= Tier.FUZZY:
                    c.consider(
                        leaf,
                        Tier.FUZZY,
                        f"product {asset.product!r} matches "
                        f"{leaf.product.product_name!r} on a low-entropy key "
                        f"{asset.key.core!r}; {ver_desc}",
                        confidence=0.45,
                    )
                continue
            if in_range is None:
                c.consider(
                    leaf,
                    Tier.EXACT,
                    f"vendor+product match but {ver_desc}",
                    verdict=Verdict.UNKNOWN,
                    confidence=0.50,
                )
                continue
            c.consider(
                leaf,
                Tier.EXACT,
                f"vendor+product match; asset version "
                f"{asset.version or '?'} satisfies {ver_desc}",
            )

    if asset.key.core and min_tier >= Tier.FUZZY:
        candidates = index.vendor_keys.get(vk, [])
        for key, ratio in _fuzzy_candidates(asset.key, candidates, fuzzy_threshold):
            for leaf in index.by_core.get((vk, key.core), ()):
                if leaf.product.key.full != key.full:
                    continue
                in_range, ver_desc = _version_clause(asset, leaf.product)
                if in_range is False:
                    continue
                note = ver_desc if in_range is True else f"{ver_desc}; version unconfirmed"
                c.consider(
                    leaf,
                    Tier.FUZZY,
                    f"fuzzy product match {asset.product!r}~"
                    f"{leaf.product.product_name!r} (ratio {ratio:.2f}); {note}",
                    confidence=round(0.60 * ratio, 3),
                )

    if min_tier >= Tier.VENDOR:
        for leaf in index.by_vendor.get(vk, ()):
            if leaf.advisory.advisory_id in c.best:
                continue
            c.consider(
                leaf,
                Tier.VENDOR,
                f"vendor {leaf.product.vendor!r} matches; product "
                f"{leaf.product.product_name!r} not confirmed against {asset.product!r}",
            )

    return list(c.best.values())


def _fuzzy_candidates(
    asset_key: ProductKey,
    candidates: Sequence[ProductKey],
    threshold: float,
) -> list[tuple[ProductKey, float]]:
    """score an asset key against the distinct product keys of one vendor."""
    if not candidates:
        return []

    out: list[tuple[ProductKey, float]] = []
    scoreable: list[str] = []
    scoreable_keys: list[ProductKey] = []

    for key in candidates:
        if not key.core:
            continue
        if key.core == asset_key.core:
            # identical core, different brand. a real candidate unless the core
            # is too generic to mean anything.
            if key.full != asset_key.full and not asset_key.low_entropy:
                out.append((key, 1.0))
            continue
        scoreable.append(key.full)
        scoreable_keys.append(key)

    for idx, ratio in fuzzy_batch(asset_key.full, scoreable, threshold):
        out.append((scoreable_keys[idx], ratio))
    return out
