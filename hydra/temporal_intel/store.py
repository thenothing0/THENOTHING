"""
TemporalStore (Phase O) — derived, event-sourced temporal ledger.

Append-only SQLite log under `data/temporal.db` (WAL). Persists temporal OBSERVATIONS and
computed snapshots (trend / forecast / health) so longitudinal metrics are reproducible from
history. Derived, disposable, rebuildable; idempotent via a UNIQUE `dedup_key`.

This store NEVER feeds back into trend computation (trends are pure functions of the underlying
learning logs) — it only records outputs/observations, so there is no chicken-and-egg and no
second canonical source. Touches nothing canonical (wiki / promotion.py / confidence.py).
"""

from __future__ import annotations

import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

_DEFAULT_DB = Path(__file__).resolve().parents[2] / "data" / "temporal.db"

KIND_OBSERVATION = "observation"
KIND_TREND = "trend_snapshot"
KIND_FORECAST = "forecast"
KIND_HEALTH = "health_metric"
_KINDS = (KIND_OBSERVATION, KIND_TREND, KIND_FORECAST, KIND_HEALTH)


@dataclass
class TemporalRecord:
    kind: str
    entity: str
    metric: str
    value: float
    occurred_at: float

    def to_dict(self) -> Dict:
        return {"kind": self.kind, "entity": self.entity, "metric": self.metric,
                "value": self.value, "occurred_at": self.occurred_at}


class TemporalStore:
    def __init__(self, db_path: Optional[Path | str] = None):
        # Precedence: explicit arg > HYDRA_TEMPORAL_DB env (test isolation) > data/.
        self.db_path = Path(db_path) if db_path else Path(
            os.environ.get("HYDRA_TEMPORAL_DB") or _DEFAULT_DB)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(str(self.db_path), timeout=30)
        c.row_factory = sqlite3.Row
        return c

    def _init(self) -> None:
        c = self._conn()
        try:
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA synchronous=NORMAL")
            c.executescript("""
                CREATE TABLE IF NOT EXISTS temporal_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    kind TEXT NOT NULL,
                    entity TEXT NOT NULL DEFAULT '',
                    metric TEXT NOT NULL DEFAULT '',
                    value REAL NOT NULL DEFAULT 0.0,
                    occurred_at REAL NOT NULL,
                    dedup_key TEXT,
                    UNIQUE(dedup_key)
                );
                CREATE INDEX IF NOT EXISTS idx_te_kind ON temporal_events(kind);
                CREATE INDEX IF NOT EXISTS idx_te_metric ON temporal_events(metric);
            """)
            c.commit()
        finally:
            c.close()

    # ── write (append-only, idempotent) ────────────────────────────────────────
    def record(self, kind: str, entity: str, metric: str, value: float,
               occurred_at: Optional[float] = None, dedup_key: Optional[str] = None) -> bool:
        if kind not in _KINDS:
            raise ValueError(f"kind must be one of {_KINDS}, got {kind!r}")
        ts = float(occurred_at) if occurred_at is not None else time.time()
        c = self._conn()
        try:
            cur = c.execute(
                "INSERT OR IGNORE INTO temporal_events (kind, entity, metric, value, "
                "occurred_at, dedup_key) VALUES (?,?,?,?,?,?)",
                (kind, entity, metric, float(value), ts, dedup_key))
            c.commit()
            return cur.rowcount == 1
        finally:
            c.close()

    def record_observation(self, entity: str, metric: str, value: float,
                           occurred_at: Optional[float] = None,
                           dedup_key: Optional[str] = None) -> bool:
        return self.record(KIND_OBSERVATION, entity, metric, value, occurred_at, dedup_key)

    # ── grouped reads (O(E)) ────────────────────────────────────────────────────
    def records(self, kind: str = "", metric: str = "") -> List[TemporalRecord]:
        where, params = [], []
        if kind:
            where.append("kind=?")
            params.append(kind)
        if metric:
            where.append("metric=?")
            params.append(metric)
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        c = self._conn()
        try:
            rows = c.execute(
                f"SELECT kind, entity, metric, value, occurred_at FROM temporal_events "
                f"{clause} ORDER BY occurred_at, id", params).fetchall()
        finally:
            c.close()
        return [TemporalRecord(r["kind"], r["entity"], r["metric"], r["value"],
                               r["occurred_at"]) for r in rows]

    def counts_by_kind(self) -> Dict[str, int]:
        c = self._conn()
        try:
            rows = c.execute(
                "SELECT kind, COUNT(*) n FROM temporal_events GROUP BY kind").fetchall()
        finally:
            c.close()
        return {r["kind"]: int(r["n"]) for r in rows}

    def summary(self) -> Dict:
        by_kind = self.counts_by_kind()
        return {"total_records": sum(by_kind.values()),
                "records_by_kind": dict(sorted(by_kind.items()))}

    def reset(self) -> None:
        c = self._conn()
        try:
            c.execute("DELETE FROM temporal_events")
            c.commit()
        finally:
            c.close()
