"""icsmatch command line interface.

stdlib argparse, so the tool installs with no package index access.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from collections import Counter
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

from .ingest.csaf import Advisory, iter_advisory_files, parse_advisory
from .ingest.enrich import Enrichment, load_epss, load_kev
from .match.engine import Asset, CorpusIndex, Tier, match_assets
from .normalize.product import HAVE_RAPIDFUZZ
from .report.markdown import ScoredMatch, render_json, render_markdown, score_matches
from .report.portfolio import ClientResult, render_portfolio
from .report.vex import render_vex
from .store.db import DEFAULT_DB, Database, bulk_load
from .store.decisions import Decision, DecisionStore

CSAF_REPO = "https://github.com/cisagov/CSAF"


def _err(msg: str) -> int:
    print(f"error: {msg}", file=sys.stderr)
    return 1


def _warn(msg: str) -> None:
    print(f"warning: {msg}", file=sys.stderr)


def _load_assets(path: Path) -> list[Asset]:
    """read an inventory, warning about rows nothing can be matched on."""
    with path.open(encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        headers = [h.strip() for h in (reader.fieldnames or []) if h]
        assets = [Asset.from_row(row) for row in reader]

    if assets and not any(a.recognised for a in assets):
        _warn(
            f"{path.name}: no usable columns found in {headers or '(no header)'}. "
            "expected at least one of vendor, product, model, cpe."
        )
    else:
        blank = [a for a in assets if not a.recognised]
        if blank:
            _warn(f"{path.name}: {len(blank)} row(s) had no vendor, product, model or cpe")
    return assets


def _decisions_path(db_path: str) -> Path:
    """decisions live beside the corpus but in their own file, so `update`
    can rebuild the corpus without putting analyst work at risk."""
    return Path(db_path).with_suffix(".decisions.db")


def _load_corpus(db_path: str) -> tuple[CorpusIndex, dict] | None:
    with Database(db_path) as db:
        if db.stats()["advisories"] == 0:
            return None
        index = CorpusIndex(db.iter_advisories())
    with DecisionStore(_decisions_path(db_path)) as ds:
        aliases = ds.load()
    return index, aliases


def _vendor_near_misses(assets: list[Asset], index: CorpusIndex) -> list[tuple[str, str]]:
    """inventory vendors the corpus does not know, with a likely intended key."""
    known = set(index.by_vendor)
    out: list[tuple[str, str]] = []
    for vk in sorted({a.vendor_key for a in assets if a.vendor_key}):
        if vk in known:
            continue
        near = [k for k in known if k.startswith(vk) or vk.startswith(k)]
        if near:
            out.append((vk, sorted(near, key=len)[0]))
    return out


def cmd_update(args: argparse.Namespace) -> int:
    src = Path(args.source).expanduser()
    if not src.exists():
        return _err(
            f"{src} not found.\n"
            f"       clone the CISA corpus first:\n"
            f"         git clone --depth 1 {CSAF_REPO} ./CSAF\n"
            f"       then: icsmatch update --source ./CSAF/csaf_files"
        )

    print(f"reading CSAF from {src}")
    collisions: list[tuple[str, str, str]] = []
    with Database(args.db) as db:
        n = bulk_load(db, _read_advisories(src, collisions))
        s = db.stats()

    print(f"loaded {n:,} advisories into {args.db}")
    print(f"  products : {s['products']:,}")
    print(f"  CVEs     : {s['cves']:,}")
    if collisions:
        print(f"\nwarning: {len(collisions)} advisory id claimed by two different")
        print("advisories in the corpus. both are kept, the second under a ~n")
        print("suffix, so no advisory is lost. links still point at the real id.")
        for aid, path, title in collisions[:5]:
            print(f"  {aid} also names {title!r}")
            print(f"    kept as {aid}~1  from {path}")
        if len(collisions) > 5:
            print(f"  and {len(collisions) - 5} more")
    return 0


def _read_advisories(
    src: Path, collisions: list[tuple[str, str, str]]
) -> Iterator[Advisory]:
    """parse every file under src, recording ids claimed by two files.

    upsert is keyed on advisory_id, so a duplicate silently replaces the
    first. the CISA corpus contains at least one, where icsa-26-225-09.json
    carries the tracking id ICSA-26-225-10.
    """
    import dataclasses

    groups: dict[str, list[tuple[str, Advisory]]] = {}
    for path in iter_advisory_files(src):
        adv = parse_advisory(path)
        if adv is not None:
            groups.setdefault(adv.advisory_id, []).append((str(path), adv))

    for aid, entries in groups.items():
        if len(entries) == 1:
            yield entries[0][1]
            continue

        # same title means one advisory published twice: keep the newer.
        # different titles mean two advisories colliding on one id, and
        # dropping either would lose findings, so both are kept.
        titles = {a.title for _, a in entries}
        if len(titles) == 1:
            entries.sort(key=lambda e: (e[1].revised, e[1].published))
            yield entries[-1][1]
            continue

        # the file whose name and directory both agree with the id keeps it.
        # VA-26-225-01 lives in VA/ and IT/ under the same filename, and only
        # the VA/ copy is where CISA's own link resolves.
        family = aid.split("-", 1)[0].upper()
        entries.sort(
            key=lambda e: (
                Path(e[0]).stem.upper() != aid.upper(),
                family not in {part.upper() for part in Path(e[0]).parts},
                e[0],
            )
        )
        for n, (origin_path, adv) in enumerate(entries):
            if n:
                collisions.append((aid, origin_path, adv.title))
                adv = dataclasses.replace(adv, advisory_id=f"{aid}~{n}")
            yield adv


def cmd_search(args: argparse.Namespace) -> int:
    with Database(args.db) as db:
        rows = db.search(args.query, limit=args.limit)
        if not rows:
            print("no matches")
            return 0
        for r in rows:
            cvss = f"{r['max_cvss']:.1f}" if r["max_cvss"] is not None else " n/a"
            patch = "" if r["has_patch"] else "  [NO PATCH]"
            print(f"{r['advisory_id']:<18} CVSS {cvss:>4}  {r['title'][:64]}{patch}")
    return 0


def _run(
    args: argparse.Namespace,
    assets: list[Asset],
    index: CorpusIndex,
    aliases: dict,
) -> list[ScoredMatch]:
    matches = match_assets(assets, index, min_tier=Tier(args.max_tier), aliases=aliases)
    enrichment = Enrichment(
        kev=load_kev(offline=args.offline),
        epss=load_epss(offline=args.offline),
    )
    return score_matches(matches, enrichment)


def cmd_match(args: argparse.Namespace) -> int:
    assets_path = Path(args.assets)
    if not assets_path.exists():
        return _err(f"{assets_path} not found")

    assets = _load_assets(assets_path)
    corpus = _load_corpus(args.db)
    if corpus is None:
        return _err("database empty, run `icsmatch update` first")
    index, aliases = corpus

    for vk, near in _vendor_near_misses(assets, index):
        _warn(f"vendor {vk!r} is not in the corpus, did you mean {near!r}?")

    scored = _run(args, assets, index, aliases)

    if args.priority:
        wanted = {p.upper() for p in args.priority}
        scored = [s for s in scored if s.priority.value in wanted]

    if args.json:
        print(render_json(scored))
        return 0

    print(f"{len(assets)} assets x {index.advisory_count:,} advisories "
          f"-> {len(scored)} findings\n")
    for s in scored[: args.limit]:
        m = s.match
        cvss = f"{m.cvss:.1f}" if m.cvss is not None else " n/a"
        kev = " KEV" if s.kev else ""
        print(f"[{s.priority.value:<5}] {m.asset.asset_id:<10} {m.advisory.advisory_id:<18} "
              f"CVSS {cvss:>4}{kev}  T{int(m.tier)}")
        print(f"          {m.basis[:100]}")
        print(f"          {s.rationale}")
    return 0


def _store_run(db_path: str, label: str, assets: int, scored: list[ScoredMatch]) -> None:
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    rows = [
        (
            s.match.asset.asset_id,
            s.match.advisory.advisory_id,
            int(s.match.tier),
            s.priority.value,
            s.match.cvss,
            s.kev,
            s.match.verdict.value,
        )
        for s in scored
    ]
    with Database(db_path) as db:
        db.record_run(label, stamp, assets, rows)


def cmd_report(args: argparse.Namespace) -> int:
    corpus = _load_corpus(args.db)
    if corpus is None:
        return _err("database empty, run `icsmatch update` first")
    index, aliases = corpus

    if args.all_clients:
        root = Path(args.all_clients)
        if not root.is_dir():
            return _err(f"{root} is not a directory")
        inventories = sorted(root.glob("*.csv"))
        if not inventories:
            return _err(f"no .csv inventories found in {root}")

        outdir = Path(args.outdir or "reports")
        outdir.mkdir(parents=True, exist_ok=True)

        results: list[ClientResult] = []
        for inv in inventories:
            assets = _load_assets(inv)
            scored = _run(args, assets, index, aliases)
            name = inv.stem
            path = outdir / f"{name}.md"
            path.write_text(
                render_markdown(
                    scored,
                    client=name,
                    total_assets=len(assets),
                    total_advisories=index.advisory_count,
                ),
                encoding="utf-8",
            )
            _store_run(args.db, name, len(assets), scored)
            results.append(
                ClientResult(
                    name=name,
                    asset_count=len(assets),
                    scored=scored,
                    report_path=path.name,
                )
            )
            print(f"  {name:<24} {len(assets):>4} assets  {len(scored):>4} findings  -> {path}")

        summary = outdir / "portfolio.md"
        summary.write_text(
            render_portfolio(results, org=args.client or ""), encoding="utf-8"
        )
        print(f"\nportfolio summary -> {summary}")
        return 0

    if not args.assets:
        return _err("provide --assets CSV or --all-clients DIR")
    assets_path = Path(args.assets)
    if not assets_path.exists():
        return _err(f"{assets_path} not found")

    assets = _load_assets(assets_path)
    scored = _run(args, assets, index, aliases)
    label = args.client or assets_path.stem
    _store_run(args.db, label, len(assets), scored)

    md = render_markdown(
        scored,
        client=label,
        total_assets=len(assets),
        total_advisories=index.advisory_count,
    )
    if args.out:
        Path(args.out).write_text(md, encoding="utf-8")
        print(f"wrote {args.out}  ({len(scored)} findings)")
    else:
        print(md)
    return 0


def cmd_vex(args: argparse.Namespace) -> int:
    """export findings as an OpenVEX document."""
    assets_path = Path(args.assets)
    if not assets_path.exists():
        return _err(f"{assets_path} not found")
    loaded = _load_corpus(args.db)
    if loaded is None:
        return _err("database empty, run `icsmatch update` first")
    index, aliases = loaded

    assets = _load_assets(assets_path)
    matches = match_assets(
        assets,
        index,
        min_tier=Tier(args.max_tier),
        aliases=aliases,
        include_not_affected=True,
    )
    doc = render_vex(matches, author=args.author)
    if args.out:
        Path(args.out).write_text(doc, encoding="utf-8")
        print(f"wrote {args.out}  ({len(matches)} findings)")
    else:
        print(doc, end="")
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    """what changed since the previous run of the same label."""
    with Database(args.db) as db:
        runs = db.last_runs(args.label, n=2)
        if not runs:
            return _err(f"no stored runs for {args.label!r}, run `icsmatch report` first")
        if len(runs) == 1:
            print(f"only one run on file for {args.label!r} ({runs[0]['ran_at']}), nothing to diff")
            return 0
        current, previous = runs[0], runs[1]
        now = db.run_findings(int(current["run_id"]))
        before = db.run_findings(int(previous["run_id"]))

    added = sorted(set(now) - set(before))
    resolved = sorted(set(before) - set(now))
    escalated = sorted(
        k for k in set(now) & set(before)
        if now[k]["priority"] != before[k]["priority"]
    )

    print(f"{args.label}: {previous['ran_at']} -> {current['ran_at']}")
    print(f"  new       {len(added)}")
    print(f"  resolved  {len(resolved)}")
    print(f"  changed   {len(escalated)}\n")

    for asset_id, advisory_id in added[: args.limit]:
        r = now[(asset_id, advisory_id)]
        print(f"  + [{r['priority']:<5}] {asset_id:<12} {advisory_id:<18} T{r['tier']}")
    for asset_id, advisory_id in resolved[: args.limit]:
        print(f"  - {'':7} {asset_id:<12} {advisory_id}")
    for asset_id, advisory_id in escalated[: args.limit]:
        print(f"  ~ {asset_id:<12} {advisory_id:<18} "
              f"{before[(asset_id, advisory_id)]['priority']} -> "
              f"{now[(asset_id, advisory_id)]['priority']}")
    return 0


def cmd_eval(args: argparse.Namespace) -> int:
    """precision and recall per tier against a labelled ground-truth file.

    the labels CSV needs asset_id, advisory_id and label, where label is
    affected or not_affected. pairs absent from the file are ignored, so a
    partial labelling still produces usable numbers.
    """
    labels_path = Path(args.labels)
    assets_path = Path(args.assets)
    for p in (labels_path, assets_path):
        if not p.exists():
            return _err(f"{p} not found")

    truth: dict[tuple[str, str], bool] = {}
    with labels_path.open(encoding="utf-8-sig", newline="") as fh:
        for row in csv.DictReader(fh):
            key = ((row.get("asset_id") or "").strip(), (row.get("advisory_id") or "").strip())
            if not all(key):
                continue
            truth[key] = (row.get("label") or "").strip().lower() in ("affected", "1", "true", "yes")

    if not truth:
        return _err(f"{labels_path} contained no usable labels")

    corpus = _load_corpus(args.db)
    if corpus is None:
        return _err("database empty, run `icsmatch update` first")
    index, aliases = corpus

    assets = _load_assets(assets_path)
    matches = match_assets(assets, index, min_tier=Tier(args.max_tier), aliases=aliases)
    predicted = {(m.asset.asset_id, m.advisory.advisory_id): m for m in matches}

    rows: list[tuple[str, int, int, int]] = []
    tiers = sorted({int(m.tier) for m in matches}) or [0]
    for cutoff in tiers:
        tp = fp = fn = 0
        for key, is_affected in truth.items():
            m = predicted.get(key)
            hit = m is not None and int(m.tier) <= cutoff
            if hit and is_affected:
                tp += 1
            elif hit and not is_affected:
                fp += 1
            elif not hit and is_affected:
                fn += 1
        rows.append((f"tier <= {cutoff}", tp, fp, fn))

    print(f"labelled pairs: {len(truth)}   predicted: {len(predicted)}\n")
    print(f"{'cutoff':<12} {'TP':>4} {'FP':>4} {'FN':>4} {'precision':>10} {'recall':>8} {'F1':>7}")
    worst = 1.0
    for name, tp, fp, fn in rows:
        rec = tp / (tp + fn) if tp + fn else 0.0
        if tp + fp == 0:
            # no predictions at this cutoff: precision is undefined, not zero,
            # and must not fail the gate. tier 0 is empty on every fresh database.
            print(f"{name:<12} {tp:>4} {fp:>4} {fn:>4} {'n/a':>10} {rec:>8.3f} {'n/a':>7}")
            continue
        prec = tp / (tp + fp)
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        worst = min(worst, prec)
        print(f"{name:<12} {tp:>4} {fp:>4} {fn:>4} {prec:>10.3f} {rec:>8.3f} {f1:>7.3f}")

    if args.min_precision and worst < args.min_precision:
        return _err(f"precision {worst:.3f} below --min-precision {args.min_precision}")
    return 0


def cmd_bench(args: argparse.Namespace) -> int:
    """time index construction and matching at several inventory sizes."""
    assets_path = Path(args.assets)
    if not assets_path.exists():
        return _err(f"{assets_path} not found")
    base = _load_assets(assets_path)
    if not base:
        return _err("inventory is empty")

    t0 = time.perf_counter()
    with Database(args.db) as db:
        if db.stats()["advisories"] == 0:
            return _err("database empty, run `icsmatch update` first")
        advisories = list(db.iter_advisories())
    t_load = time.perf_counter() - t0

    t0 = time.perf_counter()
    index = CorpusIndex(advisories)
    t_index = time.perf_counter() - t0

    print(f"rapidfuzz: {'yes' if HAVE_RAPIDFUZZ else 'no (difflib fallback)'}")
    print(f"corpus   : {index.advisory_count:,} advisories, {index.product_count:,} products")
    print(f"load     : {t_load:6.2f}s")
    print(f"index    : {t_index:6.2f}s\n")
    print(f"{'assets':>8} {'findings':>9} {'seconds':>9} {'ms/asset':>10}")

    for n in args.sizes:
        assets = [
            Asset(
                asset_id=f"A{i}",
                vendor=base[i % len(base)].vendor,
                product=base[i % len(base)].product,
                version=base[i % len(base)].version,
                model=base[i % len(base)].model,
                purdue_level=base[i % len(base)].purdue_level,
                site=base[i % len(base)].site,
            )
            for i in range(n)
        ]
        t0 = time.perf_counter()
        found = match_assets(assets, index, min_tier=Tier(args.max_tier))
        dt = time.perf_counter() - t0
        print(f"{n:>8,} {len(found):>9,} {dt:>9.2f} {dt / n * 1000:>10.3f}")
    return 0


def cmd_review(args: argparse.Namespace) -> int:
    """adjudicate fuzzy and vendor-only matches. each decision is stored once
    and reused: confirmed promotes the pair to tier 0 forever, rejected
    suppresses it forever."""
    assets_path = Path(args.assets)
    if not assets_path.exists():
        return _err(f"{assets_path} not found")

    corpus = _load_corpus(args.db)
    if corpus is None:
        return _err("database empty, run `icsmatch update` first")
    index, aliases = corpus

    assets = _load_assets(assets_path)
    matches = match_assets(assets, index, min_tier=Tier(args.max_tier), aliases=aliases)

    pending = [m for m in matches if m.tier in (Tier.FUZZY, Tier.VENDOR)]
    if not pending:
        print("nothing to review, no fuzzy or vendor-only matches outstanding")
        return 0

    seen: dict[tuple[str, str, str], list] = {}
    for m in pending:
        seen.setdefault(
            (m.asset.vendor_key, m.asset.product_key, m.product.product_key), []
        ).append(m)

    # order by impact: tier, then max CVSS, then findings covered.
    def _impact(group: list) -> tuple:
        return (
            min(m.tier for m in group),
            -max((m.cvss or 0.0) for m in group),
            -len(group),
        )

    queue = sorted(seen.items(), key=lambda kv: _impact(kv[1]))
    if args.limit:
        queue = queue[: args.limit]

    print(f"{len(queue)} product pairs to review "
          f"(of {len(seen)} outstanding, covering {len(pending)} findings)\n"
          f"[y] confirm   [n] reject   [s] skip   [q] quit\n")

    with DecisionStore(_decisions_path(args.db)) as ds:
        for i, (key, group) in enumerate(queue, 1):
            m = group[0]
            hits = sorted({x.advisory.advisory_id for x in group})
            top = max((x.cvss or 0.0) for x in group)
            print(f"[{i}/{len(queue)}] tier {int(m.tier)}  x{len(group)} findings  "
                  f"max CVSS {top:.1f}")
            print(f"  asset     : {m.asset.vendor} / {m.asset.product}"
                  f"  (e.g. {m.asset.asset_id})")
            print(f"  advisory  : {m.product.vendor} / {m.product.product_name}")
            print(f"  seen in   : {', '.join(hits[:4])}{' ...' if len(hits) > 4 else ''}")
            print(f"  basis     : {m.basis[:96]}")

            try:
                answer = input("  same product? [y/n/s/q] ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print("\naborted")
                break

            if answer == "q":
                break
            if answer == "s" or not answer:
                continue

            decision = Decision.CONFIRMED if answer == "y" else Decision.REJECTED
            ds.record(
                vendor_key=key[0],
                asset_product_key=key[1],
                adv_product_key=key[2],
                decision=decision,
                analyst=args.analyst,
                asset_product_raw=m.asset.product,
                adv_product_raw=m.product.product_name,
            )
            print(f"  {decision.value}\n")

        counts = ds.counts()

    print("\ndecisions on file:", ", ".join(f"{k} {v}" for k, v in sorted(counts.items())) or "none")
    return 0


def cmd_aliases(args: argparse.Namespace) -> int:
    with DecisionStore(_decisions_path(args.db)) as ds:
        rows = ds.export_aliases()
    if not rows:
        print("no confirmed aliases yet, run `icsmatch review`")
        return 0
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    print("# confirmed by analyst review, consider contributing to data/normalizers.yaml")
    for r in rows:
        print(f"{r['vendor']:<18} {r['asset_product']!r:<38} = {r['advisory_product']!r}")
    return 0


def cmd_stats(args: argparse.Namespace) -> int:
    with Database(args.db) as db:
        s = db.stats()
    if not s["advisories"]:
        return _err("database empty, run `icsmatch update` first")

    prods = s["products"] or 1
    ranged = s["with_version"] or 1
    advs = s["advisories"] or 1
    print("corpus")
    print(f"  advisories          {s['advisories']:>8,}")
    print(f"  products            {s['products']:>8,}")
    print(f"  unique CVEs         {s['cves']:>8,}")
    print()
    print("identifier coverage   (why CPE matching fails in OT)")
    print(f"  with CPE            {s['with_cpe']:>8,}  {100 * s['with_cpe'] / prods:5.2f}%")
    print(f"  with model numbers  {s['with_model']:>8,}  {100 * s['with_model'] / prods:5.2f}%")
    print()
    print("data quality")
    print(f"  products w/ version {s['with_version']:>8,}")
    print(f"  unparseable ranges  {s['unparseable']:>8,}  {100 * s['unparseable'] / ranged:5.2f}%"
          "  (of products carrying a version)")
    print(f"  advisories w/o patch{s['no_patch']:>8,}  {100 * s['no_patch'] / advs:5.2f}%")
    if getattr(args, "by_year", False):
        with Database(args.db) as db:
            _print_by_year(db)
    return 0


def _print_by_year(db: Database) -> None:
    """markdown table of identifier coverage by year."""
    rows = db.coverage_by_year()
    if not rows:
        return
    print("\n| Year | Products | With CPE | With model number |")
    print("|---|---:|---:|---:|")
    for yr, n, cpe, mdl in rows:
        print(f"| {yr} | {n:,} | {cpe / n:.2%} | {mdl / n:.1%} |")


def cmd_coverage(args: argparse.Namespace) -> int:
    """version-range parser coverage, measured on the source corpus."""
    from .normalize.versions import RangeKind, parse_range

    src = Path(args.source).expanduser()
    if not src.exists():
        return _err(f"{src} not found")

    kinds: Counter[str] = Counter()
    notes: Counter[str] = Counter()
    collisions: list[tuple[str, str, str]] = []
    for adv in _read_advisories(src, collisions):
        for p in adv.products:
            if not p.version_text:
                continue
            vr = parse_range(p.version_text)
            kinds[vr.kind.value] += 1
            if vr.kind is RangeKind.UNPARSEABLE:
                notes[vr.note] += 1

    total = sum(kinds.values()) or 1
    parsed = total - kinds["UNPARSEABLE"]
    print(f"version-range parser coverage: {parsed:,}/{total:,} = {100 * parsed / total:.2f}%\n")
    for k, v in kinds.most_common():
        print(f"  {v:>7,}  {100 * v / total:5.2f}%  {k}")
    if notes:
        print("\nunparseable reasons")
        for n, c in notes.most_common(12):
            print(f"  {c:>7,}  {n}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="icsmatch",
        description="Match ICS advisories against an OT asset inventory.",
    )
    p.add_argument("--db", default=str(DEFAULT_DB), help=f"database path (default: {DEFAULT_DB})")
    sub = p.add_subparsers(dest="command", required=True)

    u = sub.add_parser("update", help="ingest CSAF advisories into the database")
    u.add_argument("--source", required=True, help="path to csaf_files/ from cisagov/CSAF")
    u.set_defaults(func=cmd_update)

    s = sub.add_parser("search", help="full-text search the advisory corpus")
    s.add_argument("query")
    s.add_argument("--limit", type=int, default=25)
    s.set_defaults(func=cmd_search)

    m = sub.add_parser("match", help="match an asset inventory against advisories")
    m.add_argument("--assets", required=True, help="asset inventory CSV")
    m.add_argument("--max-tier", type=int, default=4, choices=[0, 1, 2, 3, 4, 5],
                   help="lowest-confidence tier to include (default: 4)")
    m.add_argument("--priority", nargs="*", help="filter: NOW NEXT TRACK LATER")
    m.add_argument("--limit", type=int, default=50)
    m.add_argument("--json", action="store_true", help="JSON output for downstream ingest")
    m.add_argument("--offline", action="store_true", help="use cached KEV/EPSS only")
    m.set_defaults(func=cmd_match)

    r = sub.add_parser("report", help="render a markdown triage report")
    r.add_argument("--assets", help="asset inventory CSV")
    r.add_argument("--all-clients", metavar="DIR",
                   help="directory of inventory CSVs: one report each plus a portfolio rollup")
    r.add_argument("--out", help="output path (default: stdout)")
    r.add_argument("--outdir", help="output directory for --all-clients (default: reports/)")
    r.add_argument("--client", help="name used in the report header and run label")
    r.add_argument("--max-tier", type=int, default=4, choices=[0, 1, 2, 3, 4, 5])
    r.add_argument("--offline", action="store_true")
    r.set_defaults(func=cmd_report)

    d = sub.add_parser("diff", help="what changed since the previous run")
    d.add_argument("label", help="run label, usually the inventory file stem")
    d.add_argument("--limit", type=int, default=20)
    d.set_defaults(func=cmd_diff)

    vx = sub.add_parser("vex", help="export findings as an OpenVEX document")
    vx.add_argument("--assets", required=True, help="asset inventory CSV")
    vx.add_argument("--out", help="output path (default: stdout)")
    vx.add_argument("--author", default="icsmatch", help="VEX document author")
    vx.add_argument("--max-tier", type=int, default=4, choices=[0, 1, 2, 3, 4, 5])
    vx.set_defaults(func=cmd_vex)

    ev = sub.add_parser("eval", help="precision and recall against labelled pairs")
    ev.add_argument("--assets", required=True)
    ev.add_argument("--labels", required=True,
                    help="CSV with asset_id, advisory_id, label")
    ev.add_argument("--max-tier", type=int, default=5, choices=[0, 1, 2, 3, 4, 5])
    ev.add_argument("--min-precision", type=float, default=0.0,
                    help="exit non-zero if precision falls below this")
    ev.set_defaults(func=cmd_eval)

    b = sub.add_parser("bench", help="benchmark matching throughput")
    b.add_argument("--assets", required=True)
    b.add_argument("--sizes", type=int, nargs="*", default=[100, 1000, 5000])
    b.add_argument("--max-tier", type=int, default=4, choices=[0, 1, 2, 3, 4, 5])
    b.set_defaults(func=cmd_bench)

    rv = sub.add_parser("review", help="adjudicate fuzzy matches, decisions persist")
    rv.add_argument("--assets", required=True)
    rv.add_argument("--analyst", default="", help="name recorded against each decision")
    rv.add_argument("--max-tier", type=int, default=4, choices=[4, 5],
                    help="4 = fuzzy only (default), 5 = include vendor-only")
    rv.add_argument("--limit", type=int, default=25,
                    help="pairs per session, highest impact first (0 = all)")
    rv.set_defaults(func=cmd_review)

    al = sub.add_parser("aliases", help="list analyst-confirmed aliases")
    al.add_argument("--json", action="store_true")
    al.set_defaults(func=cmd_aliases)

    st = sub.add_parser("stats", help="corpus statistics and identifier coverage")
    st.add_argument("--by-year", action="store_true",
                    help="markdown table of identifier coverage by year")
    st.set_defaults(func=cmd_stats)

    c = sub.add_parser("coverage", help="version-range parser coverage report")
    c.add_argument("--source", required=True)
    c.set_defaults(func=cmd_coverage)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
