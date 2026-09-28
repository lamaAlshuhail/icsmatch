"""sqlite store: run history and schema migration."""

from __future__ import annotations

from pathlib import Path

from icsmatch.store.db import Database

from .factories import advisory, product

# run history


def test_runs_are_recorded_and_diffable(tmp_path: Path) -> None:
    with Database(tmp_path / "t.db") as db:
        db.record_run(
            "site-a", "2026-01-01T00:00:00", 2,
            [("A1", "ICSA-1", 3, "NEXT", 7.5, False, "AFFECTED")],
        )
        db.record_run(
            "site-a", "2026-01-08T00:00:00", 2,
            [
                ("A1", "ICSA-1", 3, "NOW", 7.5, True, "AFFECTED"),
                ("A2", "ICSA-2", 1, "NEXT", 8.1, False, "AFFECTED"),
            ],
        )
        runs = db.last_runs("site-a", n=2)
        assert len(runs) == 2
        current = db.run_findings(int(runs[0]["run_id"]))
        previous = db.run_findings(int(runs[1]["run_id"]))

    assert set(current) - set(previous) == {("A2", "ICSA-2")}
    assert current[("A1", "ICSA-1")]["priority"] == "NOW"
    assert previous[("A1", "ICSA-1")]["priority"] == "NEXT"


def test_schema_bump_rebuilds_the_corpus(tmp_path: Path) -> None:
    """a schema change must not leave a half-migrated database behind."""
    path = tmp_path / "t.db"
    with Database(path) as db:
        db.upsert(advisory([product("SIMATIC S7-1200")]))
        db.commit()
        assert db.stats()["advisories"] == 1

    import sqlite3

    conn = sqlite3.connect(path)
    conn.execute("PRAGMA user_version = 1")
    conn.commit()
    conn.close()

    with Database(path) as db:
        assert db.stats()["advisories"] == 0
