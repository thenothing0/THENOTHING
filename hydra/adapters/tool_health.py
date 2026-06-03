"""
ToolHealthStore — event-sourced adapter/tool health learning (Phase K).

Tracks sandboxed adapter activity (executions / validations / simulations) and their
outcomes (success / failure / timeout) + runtime, and derives reliability metrics. Every
metric is a pure function of an append-only event log → trivially rebuildable & deterministic.

Architectural position (unchanged invariants):
  * **Derived, NOT canonical.** Lives under `data/tool_health.db` (gitignored). The wiki
    never reads or mirrors it → no dual-write. Wipe and recompute any time.
  * **Idempotent** recording via an optional `dedup_key` (UNIQUE) — retries converge.
  * **WAL** journal mode + single-query aggregation (Phase D/F lessons).
  * **No execution.** This only ACCOUNTS for the sandboxed runtime's activity; it never
    launches a tool, exploits a target, or writes the wiki.
"""

from __future__ import annotations

import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

_DEFAULT_DB = Path(__file__).resolve().parents[2] / "data" / "tool_health.db"

# Event vocabulary.
EV_EXECUTION = "execution"
EV_VALIDATION = "validation"
EV_SIMULATION = "simulation"
_EVENT_TYPES = (EV_EXECUTION, EV_VALIDATION, EV_SIMULATION)

OUTCOME_SUCCESS = "success"
OUTCOME_FAILURE = "failure"
OUTCOME_TIMEOUT = "timeout"
_OUTCOMES = (OUTCOME_SUCCESS, OUTCOME_FAILURE, OUTCOME_TIMEOUT)


@dataclass
class AdapterHealth:
    adapter_id: str
    executions: int = 0
    validations: int = 0
    simulations: int = 0
    successes: int = 0
    failures: int = 0
    timeout_count: int = 0
    average_runtime: float = 0.0       # mean runtime_ms over runtime-bearing events
    last_success_at: Optional[float] = None

    @property
    def total_outcomes(self) -> int:
        return self.successes + self.failures + self.timeout_count

    @property
    def success_rate(self) -> float:
        t = self.total_outcomes
        return round(self.successes / t, 4) if t else 0.0

    @property
    def failure_rate(self) -> float:
        t = self.total_outcomes
        return round(self.failures / t, 4) if t else 0.0

    @property
    def timeout_rate(self) -> float:
        t = self.total_outcomes
        return round(self.timeout_count / t, 4) if t else 0.0

    @property
    def reliability_score(self) -> float:
        # Laplace-smoothed success reputation → stable with little data, deterministic.
        # Timeouts count against reliability (treated as non-successes).
        return round((self.successes + 1) / (self.total_outcomes + 2), 4)

    @property
    def runtime_score(self) -> float:
        # Faster → higher, in (0, 1]. Deterministic; 1.0 when no runtime recorded.
        return round(1.0 / (1.0 + self.average_runtime / 1000.0), 4)

    def to_dict(self) -> Dict:
        return {
            "adapter_id": self.adapter_id,
            "executions": self.executions, "validations": self.validations,
            "simulations": self.simulations, "successes": self.successes,
            "failures": self.failures, "timeout_count": self.timeout_count,
            "average_runtime": round(self.average_runtime, 4),
            "last_success_at": self.last_success_at,
            "success_rate": self.success_rate, "failure_rate": self.failure_rate,
            "timeout_rate": self.timeout_rate, "reliability_score": self.reliability_score,
            "runtime_score": self.runtime_score,
        }


class ToolHealthStore:
    def __init__(self, db_path: Optional[Path | str] = None):
        # Precedence: explicit arg > HYDRA_TOOL_HEALTH_DB env (test isolation) > data/.
        self.db_path = Path(db_path) if db_path else Path(
            os.environ.get("HYDRA_TOOL_HEALTH_DB") or _DEFAULT_DB)
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
                CREATE TABLE IF NOT EXISTS health_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    adapter_id TEXT NOT NULL,
                    capability_id TEXT,
                    category TEXT,
                    event_type TEXT NOT NULL,        -- execution | validation | simulation
                    outcome TEXT NOT NULL,           -- success | failure | timeout
                    runtime_ms REAL DEFAULT 0.0,
                    dedup_key TEXT,                  -- optional; UNIQUE → idempotent
                    occurred_at REAL NOT NULL,
                    UNIQUE(dedup_key)
                );
                CREATE INDEX IF NOT EXISTS idx_he_adapter ON health_events(adapter_id);
                CREATE INDEX IF NOT EXISTS idx_he_category ON health_events(category);
            """)
            c.commit()
        finally:
            c.close()

    # ── write (append-only, idempotent on dedup_key) ─────────────────────────────
    def record(self, adapter_id: str, event_type: str, outcome: str,
               runtime_ms: float = 0.0, capability_id: str = "", category: str = "",
               dedup_key: Optional[str] = None) -> bool:
        """Append one health event. Returns True iff newly recorded."""
        if not adapter_id:
            raise ValueError("adapter_id is required")
        if event_type not in _EVENT_TYPES:
            raise ValueError(f"event_type must be one of {_EVENT_TYPES}, got {event_type!r}")
        if outcome not in _OUTCOMES:
            raise ValueError(f"outcome must be one of {_OUTCOMES}, got {outcome!r}")
        c = self._conn()
        try:
            cur = c.execute(
                "INSERT OR IGNORE INTO health_events (adapter_id, capability_id, category, "
                "event_type, outcome, runtime_ms, dedup_key, occurred_at) VALUES (?,?,?,?,?,?,?,?)",
                (adapter_id, capability_id, category, event_type, outcome,
                 float(runtime_ms), dedup_key, time.time()))
            c.commit()
            return cur.rowcount == 1
        finally:
            c.close()

    # ── read aggregation (single grouped queries → pure metrics) ─────────────────
    _AGG = (
        "SUM(event_type='execution') executions, "
        "SUM(event_type='validation') validations, "
        "SUM(event_type='simulation') simulations, "
        "SUM(outcome='success') successes, "
        "SUM(outcome='failure') failures, "
        "SUM(outcome='timeout') timeouts, "
        "AVG(CASE WHEN runtime_ms>0 THEN runtime_ms END) avg_runtime, "
        "MAX(CASE WHEN outcome='success' THEN occurred_at END) last_success"
    )

    @staticmethod
    def _row_to_health(adapter_id: str, r) -> AdapterHealth:
        return AdapterHealth(
            adapter_id=adapter_id,
            executions=int(r["executions"] or 0), validations=int(r["validations"] or 0),
            simulations=int(r["simulations"] or 0), successes=int(r["successes"] or 0),
            failures=int(r["failures"] or 0), timeout_count=int(r["timeouts"] or 0),
            average_runtime=float(r["avg_runtime"] or 0.0),
            last_success_at=r["last_success"])

    def health(self, adapter_id: str) -> AdapterHealth:
        c = self._conn()
        try:
            r = c.execute(f"SELECT {self._AGG} FROM health_events WHERE adapter_id=?",
                          (adapter_id,)).fetchone()
        finally:
            c.close()
        if r is None or r["executions"] is None and r["validations"] is None \
                and r["simulations"] is None:
            return AdapterHealth(adapter_id=adapter_id)
        return self._row_to_health(adapter_id, r)

    def all_health(self) -> List[AdapterHealth]:
        c = self._conn()
        try:
            rows = c.execute(
                f"SELECT adapter_id, {self._AGG} FROM health_events "
                "GROUP BY adapter_id").fetchall()
        finally:
            c.close()
        out = [self._row_to_health(r["adapter_id"], r) for r in rows]
        out.sort(key=lambda h: h.adapter_id)
        return out

    def category_runtime(self) -> List[Dict]:
        """Per-category mean runtime + timeout counts (single query)."""
        c = self._conn()
        try:
            rows = c.execute(
                "SELECT category, COUNT(*) events, "
                "AVG(CASE WHEN runtime_ms>0 THEN runtime_ms END) avg_runtime, "
                "SUM(outcome='timeout') timeouts FROM health_events "
                "GROUP BY category").fetchall()
        finally:
            c.close()
        out = [{"category": r["category"] or "unknown", "events": int(r["events"]),
                "average_runtime": round(float(r["avg_runtime"] or 0.0), 4),
                "timeouts": int(r["timeouts"] or 0)} for r in rows]
        out.sort(key=lambda d: d["category"])
        return out

    def reset(self) -> None:
        c = self._conn()
        try:
            c.execute("DELETE FROM health_events")
            c.commit()
        finally:
            c.close()
