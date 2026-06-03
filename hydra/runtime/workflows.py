"""
WorkflowStore + state machine + RetryPolicy (Phase I).

Derived, disposable, rebuildable SQLite store (`data/workflows.db`, WAL) holding
workflow + task records. Explicit, validated state machines; invalid transitions
raise. Never canonical — the wiki is untouched and runtime state can be wiped/rebuilt.
"""

from __future__ import annotations

import os
import sqlite3
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional

_DEFAULT_DB = Path(__file__).resolve().parents[2] / "data" / "workflows.db"


class WorkflowState(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class TaskState(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    RETRYING = "RETRYING"
    SKIPPED = "SKIPPED"


# Validated, deterministic transition graphs. Anything not listed is rejected.
WORKFLOW_TRANSITIONS: Dict[WorkflowState, set] = {
    WorkflowState.PENDING: {WorkflowState.RUNNING, WorkflowState.CANCELLED},
    WorkflowState.RUNNING: {WorkflowState.COMPLETED, WorkflowState.FAILED, WorkflowState.CANCELLED},
    WorkflowState.COMPLETED: set(),
    WorkflowState.FAILED: set(),
    WorkflowState.CANCELLED: set(),
}
TASK_TRANSITIONS: Dict[TaskState, set] = {
    TaskState.PENDING: {TaskState.RUNNING, TaskState.SKIPPED},
    TaskState.RUNNING: {TaskState.COMPLETED, TaskState.FAILED, TaskState.SKIPPED},
    TaskState.FAILED: {TaskState.RETRYING},
    TaskState.RETRYING: {TaskState.RUNNING},
    TaskState.COMPLETED: set(),
    TaskState.SKIPPED: set(),
}
_WORKFLOW_TERMINAL = {WorkflowState.COMPLETED, WorkflowState.FAILED, WorkflowState.CANCELLED}
_TASK_TERMINAL = {TaskState.COMPLETED, TaskState.SKIPPED}


class WorkflowStateError(Exception):
    """Raised on an invalid workflow/task state transition."""


def validate_workflow_transition(src: WorkflowState, dst: WorkflowState) -> None:
    if dst not in WORKFLOW_TRANSITIONS.get(src, set()):
        raise WorkflowStateError(f"invalid workflow transition {src.value} -> {dst.value}")


def validate_task_transition(src: TaskState, dst: TaskState) -> None:
    if dst not in TASK_TRANSITIONS.get(src, set()):
        raise WorkflowStateError(f"invalid task transition {src.value} -> {dst.value}")


@dataclass
class RetryPolicy:
    """Deterministic retry policy. FAILED → RETRYING until max_retries, then FAILED."""
    max_retries: int = 2
    backoff_seconds: float = 5.0      # recorded; runtime is advisory (no real sleeping)
    timeout_seconds: float = 120.0

    def backoff_for(self, attempt: int) -> float:
        """Deterministic exponential backoff (advisory, not slept)."""
        return round(self.backoff_seconds * (2 ** max(0, attempt - 1)), 4)


class WorkflowStore:
    def __init__(self, db_path: Optional[Path | str] = None):
        self.db_path = Path(db_path) if db_path else Path(
            os.environ.get("HYDRA_WORKFLOWS_DB") or _DEFAULT_DB)
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
                CREATE TABLE IF NOT EXISTS workflows (
                    workflow_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL, target_type TEXT,
                    status TEXT NOT NULL,
                    created_at REAL NOT NULL, updated_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS tasks (
                    task_id TEXT PRIMARY KEY,
                    workflow_id TEXT NOT NULL, order_idx INTEGER,
                    agent_id TEXT, capability_id TEXT, tool_id TEXT,
                    status TEXT NOT NULL, attempts INTEGER DEFAULT 0,
                    started_at REAL, completed_at REAL, failure_reason TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_tasks_wf ON tasks(workflow_id);
            """)
            c.commit()
        finally:
            c.close()

    # ── workflow records ─────────────────────────────────────────────────────
    def create_workflow(self, workflow_id: str, target: str, target_type: str,
                        tasks: List[Dict]) -> bool:
        """Idempotent create (deterministic workflow_id). Returns True if newly created.
        Re-creating the same workflow does not duplicate or mutate it."""
        now = time.time()
        c = self._conn()
        try:
            cur = c.execute(
                "INSERT OR IGNORE INTO workflows (workflow_id, target, target_type, status, "
                "created_at, updated_at) VALUES (?,?,?,?,?,?)",
                (workflow_id, target, target_type, WorkflowState.PENDING.value, now, now))
            created = cur.rowcount == 1
            if created:
                for t in tasks:
                    c.execute(
                        "INSERT OR IGNORE INTO tasks (task_id, workflow_id, order_idx, agent_id, "
                        "capability_id, tool_id, status, attempts) VALUES (?,?,?,?,?,?,?,0)",
                        (t["task_id"], workflow_id, t["order_idx"], t.get("agent_id"),
                         t.get("capability_id"), t.get("tool_id"), TaskState.PENDING.value))
            c.commit()
            return created
        finally:
            c.close()

    def get_workflow(self, workflow_id: str) -> Optional[Dict]:
        c = self._conn()
        try:
            row = c.execute("SELECT * FROM workflows WHERE workflow_id=?", (workflow_id,)).fetchone()
        finally:
            c.close()
        return dict(row) if row else None

    def get_tasks(self, workflow_id: str) -> List[Dict]:
        c = self._conn()
        try:
            rows = c.execute("SELECT * FROM tasks WHERE workflow_id=? ORDER BY order_idx, task_id",
                             (workflow_id,)).fetchall()
        finally:
            c.close()
        return [dict(r) for r in rows]

    def set_workflow_status(self, workflow_id: str, status: WorkflowState) -> None:
        c = self._conn()
        try:
            c.execute("UPDATE workflows SET status=?, updated_at=? WHERE workflow_id=?",
                      (status.value, time.time(), workflow_id))
            c.commit()
        finally:
            c.close()

    def update_task(self, task_id: str, **fields) -> None:
        if not fields:
            return
        cols = ", ".join(f"{k}=?" for k in fields)
        c = self._conn()
        try:
            c.execute(f"UPDATE tasks SET {cols} WHERE task_id=?",
                      (*fields.values(), task_id))
            c.commit()
        finally:
            c.close()

    def list_workflows(self) -> List[Dict]:
        c = self._conn()
        try:
            rows = c.execute("SELECT * FROM workflows ORDER BY created_at, workflow_id").fetchall()
        finally:
            c.close()
        return [dict(r) for r in rows]

    def all_tasks(self) -> List[Dict]:
        c = self._conn()
        try:
            rows = c.execute("SELECT * FROM tasks").fetchall()
        finally:
            c.close()
        return [dict(r) for r in rows]

    def reset(self) -> None:
        c = self._conn()
        try:
            c.executescript("DELETE FROM tasks; DELETE FROM workflows;")
            c.commit()
        finally:
            c.close()
