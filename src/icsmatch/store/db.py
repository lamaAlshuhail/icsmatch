"""SQLite persistence with FTS5 search.

one file, no server, works air-gapped. the whole CISA corpus lands in tens of
megabytes and searches in single-digit milliseconds.

the schema carries a version. when it changes, or when normalisation changes
and the stored keys go stale, the corpus tables are rebuilt on next open.
analyst decisions live in a separate file and are never touched.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Iterable, Iterator
from pathlib import Path

from ..ingest.csaf import Advisory, CSAFProduct, CSAFVuln
from ..normalize.versions import parse_range

__all__ = ["Database", "DEFAULT_DB", "SCHEMA_VERSION", "fts_query", "bulk_load"]

DEFAULT_DB = Path.home() / ".cache" / "icsmatch" / "icsmatch.db"
SCHEMA_VERSION = 4

_SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous  = NORMAL;

CREATE TABLE IF NOT EXISTS advisories (
    advisory_id TEXT PRIMARY KEY,
    title       TEXT NOT NULL,
    published   TEXT,
    revised     TEXT,
    severity    TEXT,
    publisher   TEXT,
    summary     TEXT,
    sectors     TEXT,
    max_cvss    REAL,
    has_patch   INTEGER,
    tlp         TEXT,
    source_path TEXT
);

CREATE TABLE IF NOT EXISTS products (
    product_id    TEXT NOT NULL,
    advisory_id   TEXT NOT NULL REFERENCES advisories(advisory_id) ON DELETE CASCADE,
    vendor        TEXT,
    vendor_key    TEXT,
    product_name  TEXT,
    product_key   TEXT,
    full_name     TEXT,
    version_text  TEXT,
    range_kind    TEXT,
    model_numbers TEXT,
    skus          TEXT,
    cpe           TEXT,
    PRIMARY KEY (advisory_id, product_id)
);

CREATE TABLE IF NOT EXISTS vulns (
    cve         TEXT NOT NULL,
    advisory_id TEXT NOT NULL REFERENCES advisories(advisory_id) ON DELETE CASCADE,
    cwe         TEXT,
    title       TEXT,
    cvss_score  REAL,
    cvss_vector TEXT,
    affected    TEXT,
    status      TEXT,
    has_remedy  INTEGER,
    PRIMARY KEY (advisory_id, cve)
);

CREATE TABLE IF NOT EXISTS runs (
    run_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    label      TEXT NOT NULL,
    ran_at     TEXT NOT NULL,
    assets     INTEGER,
    findings   INTEGER
);

CREATE TABLE IF NOT EXISTS findings (
    run_id      INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    asset_id    TEXT NOT NULL,
    advisory_id TEXT NOT NULL,
    tier        INTEGER,
    priority    TEXT,
    cvss        REAL,
    kev         INTEGER,
    verdict     TEXT,
    PRIMARY KEY (run_id, asset_id, advisory_id)
);

CREATE INDEX IF NOT EXISTS idx_products_vendor  ON products(vendor_key);
CREATE INDEX IF NOT EXISTS idx_products_product ON products(product_key);
CREATE INDEX IF NOT EXISTS idx_products_adv     ON products(advisory_id);
CREATE INDEX IF NOT EXISTS idx_vulns_cve        ON vulns(cve);
CREATE INDEX IF NOT EXISTS idx_runs_label       ON runs(label, ran_at);

CREATE VIRTUAL TABLE IF NOT EXISTS advisories_fts USING fts5(
    advisory_id UNINDEXED,
    title,
    summary,
    vendors,
    products,
    tokenize = 'porter unicode61'
);
"""

_CORPUS_TABLES = ("advisories", "products", "vulns", "advisories_fts")

_FTS_TOKEN = re.compile(r"[A-Za-z0-9_]+")


def fts_query(text: str) -> str:
    """turn arbitrary user input into a safe FTS5 MATCH expression.

    FTS5 treats -, ", *, ^, : and the words AND/OR/NOT as syntax, so a query
    like S7-1200 or allen-bradley raises OperationalError. every token is
    quoted as a phrase and the tokens are ANDed.
    """
    tokens = _FTS_TOKEN.findall(text or "")
    return " ".join(f'"{t}"' for t in tokens)


class Database:
    """thin wrapper over a SQLite connection, usable as a context manager."""

    def __init__(self, path: Path | str = DEFAULT_DB) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self._migrate()
        self.conn.executescript(_SCHEMA)

    def _migrate(self) -> None:
        """drop corpus tables when the schema version moved. decisions are in
        a separate file, so nothing an analyst produced is at risk."""
        found = self.conn.execute("PRAGMA user_version").fetchone()[0]
        if found == SCHEMA_VERSION:
            return
        if found:
            for table in _CORPUS_TABLES:
                self.conn.execute(f"DROP TABLE IF EXISTS {table}")
            self.conn.commit()
        self.conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    def __enter__(self) -> Database:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self.conn.commit()
        self.conn.close()

    def upsert(self, adv: Advisory) -> None:
        c = self.conn
        c.execute("DELETE FROM advisories WHERE advisory_id = ?", (adv.advisory_id,))
        c.execute("DELETE FROM products   WHERE advisory_id = ?", (adv.advisory_id,))
        c.execute("DELETE FROM vulns      WHERE advisory_id = ?", (adv.advisory_id,))
        c.execute("DELETE FROM advisories_fts WHERE advisory_id = ?", (adv.advisory_id,))

        c.execute(
            "INSERT INTO advisories VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                adv.advisory_id,
                adv.title,
                adv.published,
                adv.revised,
                adv.severity,
                adv.publisher,
                adv.summary,
                json.dumps(adv.sectors),
                adv.max_cvss,
                int(adv.has_patch),
                adv.tlp,
                adv.source_path,
            ),
        )

        c.executemany(
            "INSERT OR REPLACE INTO products VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            [
                (
                    p.product_id,
                    adv.advisory_id,
                    p.vendor,
                    p.vendor_key,
                    p.product_name,
                    p.product_key,
                    p.full_name,
                    p.version_text,
                    p.version_range.kind.value,
                    json.dumps(p.model_numbers),
                    json.dumps(p.skus),
                    p.cpe,
                )
                for p in adv.products
            ],
        )

        c.executemany(
            "INSERT OR REPLACE INTO vulns VALUES (?,?,?,?,?,?,?,?,?)",
            [
                (
                    v.cve,
                    adv.advisory_id,
                    v.cwe,
                    v.title,
                    v.cvss_score,
                    v.cvss_vector,
                    json.dumps(v.known_affected),
                    json.dumps(v.status),
                    int(bool(v.remediations)),
                )
                for v in adv.vulns
                if v.cve
            ],
        )

        c.execute(
            "INSERT INTO advisories_fts VALUES (?,?,?,?,?)",
            (
                adv.advisory_id,
                adv.title,
                adv.summary,
                " ".join(sorted({p.vendor for p in adv.products if p.vendor})),
                " ".join(sorted({p.product_name for p in adv.products if p.product_name})),
            ),
        )

    def commit(self) -> None:
        self.conn.commit()

    def search(self, query: str, limit: int = 25) -> list[sqlite3.Row]:
        """full-text search across title, summary, vendor and product names."""
        expr = fts_query(query)
        if not expr:
            return []
        try:
            return list(
                self.conn.execute(
                    """
                    SELECT a.*, bm25(advisories_fts) AS rank
                    FROM advisories_fts
                    JOIN advisories a USING (advisory_id)
                    WHERE advisories_fts MATCH ?
                    ORDER BY rank
                    LIMIT ?
                    """,
                    (expr, limit),
                )
            )
        except sqlite3.OperationalError:
            return []

    def coverage_by_year(self, since: int = 2020) -> list[tuple[str, int, int, int]]:
        """(year, products, with_cpe, with_model_number), for the write-up table."""
        rows = self.conn.execute(
            """
            SELECT substr(a.published, 1, 4)                       AS yr,
                   COUNT(*)                                        AS n,
                   SUM(CASE WHEN p.cpe != '' THEN 1 ELSE 0 END)    AS cpe,
                   SUM(CASE WHEN p.model_numbers NOT IN ('[]', '')
                            THEN 1 ELSE 0 END)                     AS mdl
            FROM products p JOIN advisories a USING (advisory_id)
            WHERE yr GLOB '[0-9][0-9][0-9][0-9]' AND CAST(yr AS INTEGER) >= ?
            GROUP BY yr ORDER BY yr
            """,
            (since,),
        ).fetchall()
        return [(r["yr"], r["n"], r["cpe"], r["mdl"]) for r in rows]

    def stats(self) -> dict[str, int | float]:
        row = self.conn.execute(
            """
            SELECT
              (SELECT COUNT(*) FROM advisories)                    AS advisories,
              (SELECT COUNT(*) FROM products)                      AS products,
              (SELECT COUNT(DISTINCT cve) FROM vulns)              AS cves,
              (SELECT COUNT(*) FROM products WHERE cpe   != '')    AS with_cpe,
              (SELECT COUNT(*) FROM products
                 WHERE model_numbers NOT IN ('[]',''))             AS with_model,
              (SELECT COUNT(*) FROM products
                 WHERE version_text != '')                         AS with_version,
              (SELECT COUNT(*) FROM products
                 WHERE version_text != '' AND range_kind = 'UNPARSEABLE')
                                                                   AS unparseable,
              (SELECT COUNT(*) FROM advisories WHERE has_patch=0)  AS no_patch
            """
        ).fetchone()
        return dict(row)

    def iter_advisories(self) -> Iterator[Advisory]:
        """rehydrate every advisory. used by the matcher."""
        prods: dict[str, list[CSAFProduct]] = {}
        for r in self.conn.execute("SELECT * FROM products"):
            prods.setdefault(r["advisory_id"], []).append(
                CSAFProduct(
                    product_id=r["product_id"],
                    vendor=r["vendor"] or "",
                    product_name=r["product_name"] or "",
                    version_text=r["version_text"] or "",
                    version_range=parse_range(r["version_text"] or ""),
                    full_name=r["full_name"] or "",
                    model_numbers=json.loads(r["model_numbers"] or "[]"),
                    skus=json.loads(r["skus"] or "[]"),
                    cpe=r["cpe"] or "",
                )
            )

        vulns: dict[str, list[CSAFVuln]] = {}
        for r in self.conn.execute("SELECT * FROM vulns"):
            vulns.setdefault(r["advisory_id"], []).append(
                CSAFVuln(
                    cve=r["cve"],
                    cwe=r["cwe"] or "",
                    title=r["title"] or "",
                    cvss_score=r["cvss_score"],
                    cvss_vector=r["cvss_vector"] or "",
                    known_affected=json.loads(r["affected"] or "[]"),
                    remediations=["(recorded)"] if r["has_remedy"] else [],
                    status=json.loads(r["status"] or "{}"),
                )
            )

        for r in self.conn.execute("SELECT * FROM advisories"):
            aid = r["advisory_id"]
            yield Advisory(
                advisory_id=aid,
                title=r["title"] or "",
                published=r["published"] or "",
                revised=r["revised"] or "",
                severity=r["severity"] or "",
                publisher=r["publisher"] or "",
                summary=r["summary"] or "",
                products=prods.get(aid, []),
                vulns=vulns.get(aid, []),
                sectors=json.loads(r["sectors"] or "[]"),
                source_path=r["source_path"] or "",
                tlp=r["tlp"] or "",
            )

    def record_run(
        self,
        label: str,
        ran_at: str,
        assets: int,
        rows: Iterable[tuple[str, str, int, str, float | None, bool, str]],
    ) -> int:
        """store one run's findings so the next run can diff against it."""
        cur = self.conn.execute(
            "INSERT INTO runs (label, ran_at, assets, findings) VALUES (?,?,?,0)",
            (label, ran_at, assets),
        )
        run_id = int(cur.lastrowid or 0)
        payload = [(run_id, *r[:3], r[3], r[4], int(r[5]), r[6]) for r in rows]
        self.conn.executemany(
            "INSERT OR REPLACE INTO findings VALUES (?,?,?,?,?,?,?,?)", payload
        )
        self.conn.execute(
            "UPDATE runs SET findings = ? WHERE run_id = ?", (len(payload), run_id)
        )
        self.conn.commit()
        return run_id

    def last_runs(self, label: str, n: int = 2) -> list[sqlite3.Row]:
        return list(
            self.conn.execute(
                "SELECT * FROM runs WHERE label = ? ORDER BY run_id DESC LIMIT ?",
                (label, n),
            )
        )

    def run_findings(self, run_id: int) -> dict[tuple[str, str], sqlite3.Row]:
        return {
            (r["asset_id"], r["advisory_id"]): r
            for r in self.conn.execute("SELECT * FROM findings WHERE run_id = ?", (run_id,))
        }


def bulk_load(db: Database, advisories: Iterable[Advisory], every: int = 250) -> int:
    n = 0
    for adv in advisories:
        db.upsert(adv)
        n += 1
        if n % every == 0:
            db.commit()
    db.commit()
    return n
