"""analyst decisions and learned aliases.

tier 4 and tier 5 matches are leads that an analyst has to adjudicate.
`icsmatch review` stores each decision: a confirmed pair becomes a learned
alias promoted to tier 0 with the analyst cited, a rejected pair is
suppressed.

decisions are keyed on (vendor_key, asset_product_key, advisory_product_key)
rather than on advisory id, so one decision generalises across every advisory
naming that product.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

__all__ = ["Decision", "DecisionStore", "LearnedAlias"]


class Decision(str, Enum):
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    DEFERRED = "DEFERRED"


_SCHEMA = """
CREATE TABLE IF NOT EXISTS decisions (
    vendor_key          TEXT NOT NULL,
    asset_product_key   TEXT NOT NULL,
    adv_product_key     TEXT NOT NULL,
    decision            TEXT NOT NULL,
    analyst             TEXT,
    decided_at          TEXT,
    note                TEXT,
    asset_product_raw   TEXT,
    adv_product_raw     TEXT,
    PRIMARY KEY (vendor_key, asset_product_key, adv_product_key)
);

CREATE INDEX IF NOT EXISTS idx_decisions_lookup
    ON decisions(vendor_key, asset_product_key);
"""


@dataclass(frozen=True)
class LearnedAlias:
    vendor_key: str
    asset_product_key: str
    adv_product_key: str
    decision: Decision
    analyst: str = ""
    decided_at: str = ""
    note: str = ""
    asset_product_raw: str = ""
    adv_product_raw: str = ""

    @property
    def basis(self) -> str:
        who = f" by {self.analyst}" if self.analyst else ""
        when = f" on {self.decided_at[:10]}" if self.decided_at else ""
        if self.decision is Decision.REJECTED:
            return (
                f"analyst rejected {self.asset_product_raw!r} as "
                f"{self.adv_product_raw!r}{who}{when}"
            )
        return (
            f"analyst-confirmed alias {self.asset_product_raw!r} = "
            f"{self.adv_product_raw!r}{who}{when}"
        )


class DecisionStore:
    """persisted analyst decisions, stored beside the advisory database."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)

    def __enter__(self) -> DecisionStore:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self.conn.commit()
        self.conn.close()

    def record(
        self,
        *,
        vendor_key: str,
        asset_product_key: str,
        adv_product_key: str,
        decision: Decision,
        analyst: str = "",
        note: str = "",
        asset_product_raw: str = "",
        adv_product_raw: str = "",
    ) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO decisions VALUES (?,?,?,?,?,?,?,?,?)",
            (
                vendor_key,
                asset_product_key,
                adv_product_key,
                decision.value,
                analyst,
                datetime.now(timezone.utc).isoformat(timespec="seconds"),
                note,
                asset_product_raw,
                adv_product_raw,
            ),
        )
        self.conn.commit()

    def load(self) -> dict[tuple[str, str, str], LearnedAlias]:
        """all decisions, keyed for constant-time lookup during matching."""
        out: dict[tuple[str, str, str], LearnedAlias] = {}
        for r in self.conn.execute("SELECT * FROM decisions"):
            key = (r["vendor_key"], r["asset_product_key"], r["adv_product_key"])
            out[key] = LearnedAlias(
                vendor_key=r["vendor_key"],
                asset_product_key=r["asset_product_key"],
                adv_product_key=r["adv_product_key"],
                decision=Decision(r["decision"]),
                analyst=r["analyst"] or "",
                decided_at=r["decided_at"] or "",
                note=r["note"] or "",
                asset_product_raw=r["asset_product_raw"] or "",
                adv_product_raw=r["adv_product_raw"] or "",
            )
        return out

    def counts(self) -> dict[str, int]:
        rows = self.conn.execute(
            "SELECT decision, COUNT(*) n FROM decisions GROUP BY decision"
        ).fetchall()
        return {r["decision"]: r["n"] for r in rows}

    def export_aliases(self) -> list[dict[str, str]]:
        """confirmed aliases, shaped for contribution back to normalizers.yaml."""
        return [
            {
                "vendor": r["vendor_key"],
                "asset_product": r["asset_product_raw"],
                "advisory_product": r["adv_product_raw"],
            }
            for r in self.conn.execute(
                "SELECT * FROM decisions WHERE decision = 'CONFIRMED' "
                "ORDER BY vendor_key, asset_product_raw"
            )
        ]
