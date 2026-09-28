"""command line: full text search and advisory ingest."""

from __future__ import annotations

from pathlib import Path

import pytest

from icsmatch.store.db import Database, fts_query

from .factories import advisory, product

# full text search


@pytest.mark.parametrize(
    "query",
    ["S7-1200", "allen-bradley", 'siemens AND "', "schneider OR", "*", "", "6ES7214-1AG40-0XB0"],
)
def test_search_never_raises_on_real_product_names(tmp_path: Path, query: str) -> None:
    with Database(tmp_path / "t.db") as db:
        db.upsert(advisory([product("SIMATIC S7-1200")]))
        db.commit()
        assert isinstance(db.search(query), list)


def test_fts_query_quotes_every_token() -> None:
    assert fts_query("S7-1200") == '"S7" "1200"'
    assert fts_query("allen-bradley") == '"allen" "bradley"'
    assert fts_query('bad " input') == '"bad" "input"'
    assert fts_query("   ") == ""


def test_search_still_finds_what_it_should(tmp_path: Path) -> None:
    with Database(tmp_path / "t.db") as db:
        db.upsert(advisory([product("SIMATIC S7-1200")]))
        db.commit()
        assert db.search("siemens")
        assert db.search("S7-1200")


# an advisory id claimed by two files must not vanish silently


def _writeadvisory(tmp_path: Path, name: str, aid: str, title: str,
                    products: int = 1, revised: str = "2026-01-01") -> None:
    import json

    doc = {
        "document": {
            "tracking": {"id": aid, "initial_release_date": "2026-01-01",
                         "current_release_date": revised, "version": "1"},
            "title": title, "category": "csaf_security_advisory",
            "publisher": {"name": "CISA"},
        },
        "product_tree": {"branches": [{
            "category": "vendor", "name": "Siemens",
            "branches": [{
                "category": "product_name", "name": f"Widget {i}",
                "branches": [{"category": "product_version", "name": "1.0",
                              "product": {"product_id": f"P{i}",
                                          "name": f"Siemens Widget {i} 1.0"}}],
            } for i in range(products)],
        }]},
        "vulnerabilities": [],
    }
    (tmp_path / name).write_text(json.dumps(doc), encoding="utf-8")


def test_same_advisory_twice_keeps_the_newer_revision(tmp_path: Path) -> None:
    from icsmatch.cli import _read_advisories

    _writeadvisory(tmp_path, "a.json", "ICSA-26-000-01", "Siemens Widget",
                    products=1, revised="2026-01-01")
    _writeadvisory(tmp_path, "b.json", "ICSA-26-000-01", "Siemens Widget",
                    products=3, revised="2026-06-01")

    collisions: list[tuple[str, str, str]] = []
    got = list(_read_advisories(tmp_path, collisions))
    assert len(got) == 1
    assert len(got[0].products) == 3, "the later revision wins"
    assert collisions == [], "a revision is not a collision"


def test_two_different_advisories_on_one_id_are_both_kept(tmp_path: Path) -> None:
    """the CISA corpus holds two of these.

    icsa-26-225-09.json carries id ICSA-26-225-10 for a different advisory
    than icsa-26-225-10.json, and va-26-225-01.json exists twice with
    different content. dropping either loses findings outright.
    """
    from icsmatch.cli import _read_advisories

    _writeadvisory(tmp_path, "icsa-26-225-10.json", "ICSA-26-225-10", "Siemens Parasolid")
    _writeadvisory(tmp_path, "icsa-26-225-09.json", "ICSA-26-225-10",
                    "Siemens Siveillance Video")

    collisions: list[tuple[str, str, str]] = []
    got = list(_read_advisories(tmp_path, collisions))

    assert len(got) == 2, "neither advisory may be dropped"
    ids = {a.advisory_id for a in got}
    assert ids == {"ICSA-26-225-10", "ICSA-26-225-10~1"}
    assert {a.base_id for a in got} == {"ICSA-26-225-10"}, "links stay valid"
    assert len(collisions) == 1
    assert collisions[0][0] == "ICSA-26-225-10"


def test_the_filename_matching_the_id_keeps_the_unsuffixed_id(tmp_path: Path) -> None:
    from icsmatch.cli import _read_advisories

    _writeadvisory(tmp_path, "icsa-26-225-09.json", "ICSA-26-225-10", "Wrong File")
    _writeadvisory(tmp_path, "icsa-26-225-10.json", "ICSA-26-225-10", "Right File")

    collisions: list[tuple[str, str, str]] = []
    canonical = {a.advisory_id: a.title for a in _read_advisories(tmp_path, collisions)}
    assert canonical["ICSA-26-225-10"] == "Right File"
    assert canonical["ICSA-26-225-10~1"] == "Wrong File"


def test_no_collision_reported_for_a_clean_corpus(tmp_path: Path) -> None:
    from icsmatch.cli import _read_advisories

    collisions: list[tuple[str, str, str]] = []
    list(_read_advisories(tmp_path, collisions))
    assert collisions == []


# a cutoff with no predictions has undefined precision and must not fail the gate


def test_no_matches_at_all_does_not_fail_the_precision_gate(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """a CI corpus slice may hold none of the labelled advisories. zero
    predictions is undefined precision, not 0.0, and the gate used to fail."""
    import csv

    from icsmatch.cli import main
    from icsmatch.store.db import Database, bulk_load

    db = tmp_path / "t.db"
    with Database(db) as d:
        bulk_load(d, [advisory([product("SIMATIC S7-1200", "<V4.5")], aid="ICSA-26-000-01")])

    inv = tmp_path / "inv.csv"
    with inv.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["asset_id", "vendor", "product", "version"])
        w.writerow(["RTU-1", "Nobody Corp", "Widget", "1.0"])

    labels = tmp_path / "labels.csv"
    with labels.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["asset_id", "advisory_id", "label"])
        w.writerow(["RTU-1", "ICSA-99-999-99", "affected"])

    rc = main(["--db", str(db), "eval", "--assets", str(inv), "--labels", str(labels),
               "--max-tier", "3", "--min-precision", "0.95"])
    out = capsys.readouterr().out
    assert rc == 0, out
    assert "n/a" in out
