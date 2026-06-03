"""
SourceMetricsStore — derived, rebuildable per-source performance store (Phase C.5).

This is the persistence foundation that Phase D (source-performance learning) will
write to. It is introduced now, deliberately, so the storage decision is made before
any learning code exists.

Architectural position (non-negotiable):
  * **Derived, NOT canonical.** The wiki remains the single source of truth. These are
    high-frequency operational counters (how often a recon source fires, how many
    unique assets it found, its success rate) that do not belong in markdown.
  * **NOT a dual-write.** Nothing in the wiki mirrors these numbers; the wiki never
    reads them. They live entirely under `data/` (gitignored) and can be wiped and
    recomputed from run history at any time (`reset()` / future `rebuild_from(...)`).
  * **Keyed by the stable `source.id`** (e.g. `source.fofa`) — never the display name —
    so renames never break history and Phase D needs no migration.

Phase C.5 ships only the STORE (record / read / aggregate / reset). The learning loop
that feeds it and the planner preference that consumes it are Phase D.
"""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

# data/ is gitignored — derived artifacts only.
_DEFAULT_DB = Path(__file__).resolve().parents[2] / "data" / "source_metrics.db"


@dataclass
class SourceMetrics:
    """Aggregated, read-side view of one source's performance (keyed by source_id)."""
    source_id: str
    runs: int = 0
    discoveries: int = 0
    unique_assets: int = 0
    duplicates: int = 0
    successes: int = 0
    total_value: float = 0.0

    @property
    def success_rate(self) -> float:
        return round(self.successes / self.runs, 4) if self.runs else 0.0

    @property
    def average_value(self) -> float:
        return round(self.total_value / self.discoveries, 4) if self.discoveries else 0.0

    @property
    def duplicate_rate(self) -> float:
        return round(self.duplicates / self.discoveries, 4) if self.discoveries else 0.0

    def to_dict(self) -> Dict:
        return {
            "source_id": self.source_id, "runs": self.runs,
            "discoveries": self.discoveries, "unique_assets": self.unique_assets,
            "duplicates": self.duplicates, "successes": self.successes,
            "total_value": round(self.total_value, 4),
            "success_rate": self.success_rate, "average_value": self.average_value,
            "duplicate_rate": self.duplicate_rate,
        }


class SourceMetricsStore:
    """SQLite-backed, append-then-aggregate per-source metrics. Derived & rebuildable."""

    def __init__(self, db_path: Optional[Path | str] = None):
        self.db_path = Path(db_path) if db_path else _DEFAULT_DB
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init(self) -> None:
        conn = self._conn()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS source_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_id TEXT NOT NULL,          -- stable source.id (primary key dimension)
                    discoveries INTEGER DEFAULT 0,
                    unique_assets INTEGER DEFAULT 0,
                    duplicates INTEGER DEFAULT 0,
                    success INTEGER DEFAULT 0,         -- 1/0
                    value REAL DEFAULT 0.0,
                    recorded_at REAL NOT NULL
                )""")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_source_runs_id ON source_runs(source_id)")
            conn.commit()
        finally:
            conn.close()

    # ── write (append-only run records) ─────────────────────────────────────
    def record_run(self, source_id: str, *, discoveries: int = 0, unique_assets: int = 0,
                   duplicates: int = 0, success: bool = True, value: float = 0.0) -> None:
        """Append one source-run observation. Append-only keeps it crash-safe and
        trivially rebuildable; aggregation happens on read."""
        if not source_id:
            raise ValueError("source_id is required (stable source.* id)")
        conn = self._conn()
        try:
            conn.execute(
                "INSERT INTO source_runs (source_id, discoveries, unique_assets, "
                "duplicates, success, value, recorded_at) VALUES (?,?,?,?,?,?,?)",
                (source_id, int(discoveries), int(unique_assets), int(duplicates),
                 1 if success else 0, float(value), time.time()),
            )
            conn.commit()
        finally:
            conn.close()

    # ── read (aggregate views) ──────────────────────────────────────────────
    def get(self, source_id: str) -> SourceMetrics:
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT COUNT(*) runs, COALESCE(SUM(discoveries),0) d, "
                "COALESCE(SUM(unique_assets),0) u, COALESCE(SUM(duplicates),0) dup, "
                "COALESCE(SUM(success),0) s, COALESCE(SUM(value),0.0) v "
                "FROM source_runs WHERE source_id = ?", (source_id,)).fetchone()
        finally:
            conn.close()
        return SourceMetrics(source_id, runs=row["runs"], discoveries=row["d"],
                             unique_assets=row["u"], duplicates=row["dup"],
                             successes=row["s"], total_value=row["v"])

    def all(self) -> List[SourceMetrics]:
        conn = self._conn()
        try:
            ids = [r["source_id"] for r in conn.execute(
                "SELECT DISTINCT source_id FROM source_runs ORDER BY source_id").fetchall()]
        finally:
            conn.close()
        return [self.get(sid) for sid in ids]

    # ── lifecycle (derived ⇒ disposable) ────────────────────────────────────
    def reset(self) -> None:
        """Wipe all metrics. Safe: the store is derived and can be recomputed."""
        conn = self._conn()
        try:
            conn.execute("DELETE FROM source_runs")
            conn.commit()
        finally:
            conn.close()
