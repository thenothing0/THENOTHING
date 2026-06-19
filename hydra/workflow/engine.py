"""Pentest lifecycle state machine with checkpoints, approvals, and recovery."""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Callable, Dict, List, Optional

# The lifecycle. Linear forward path; any state can halt; halted resumes in place.
STATES = ("scope", "recon", "enumeration", "validation", "exploitation",
          "evidence", "coverage_review", "reporting", "done")

# Allowed forward transitions (each state → its successor). `reporting` can loop
# back to `exploitation` for a retest, mirroring real engagements.
TRANSITIONS: Dict[str, set] = {
    "scope": {"recon"},
    "recon": {"enumeration"},
    "enumeration": {"validation"},
    "validation": {"exploitation", "coverage_review"},  # may skip exploit → review
    "exploitation": {"evidence"},
    "evidence": {"coverage_review"},
    "coverage_review": {"reporting", "enumeration"},     # loop back if gaps remain
    "reporting": {"done", "exploitation"},               # retest loop
    "done": set(),
}

# Transitions whose TARGET state is high-consequence → require approval.
_APPROVAL_REQUIRED = {"exploitation", "evidence"}


class WorkflowError(RuntimeError):
    """Illegal transition, missing precondition, or denied approval."""


class PentestWorkflow:
    def __init__(self, db_path: str = ".thenothing/workflows/pentest.db"):
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self._path)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        return c

    def _init(self) -> None:
        with self._conn() as c:
            c.executescript(
                """
                CREATE TABLE IF NOT EXISTS runs (
                  id TEXT PRIMARY KEY, engagement_id TEXT, target TEXT,
                  state TEXT NOT NULL DEFAULT 'scope',
                  status TEXT NOT NULL DEFAULT 'running',   -- running|halted|done|failed
                  checkpoint TEXT, created_at TEXT NOT NULL, updated_at TEXT
                );
                CREATE TABLE IF NOT EXISTS events (
                  id TEXT PRIMARY KEY, run_id TEXT NOT NULL, from_state TEXT, to_state TEXT,
                  approval TEXT, note TEXT, ts TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_runs_status ON runs(status);
                CREATE INDEX IF NOT EXISTS idx_events_run ON events(run_id);
                """
            )

    # ── lifecycle ────────────────────────────────────────────────────────────────
    def create(self, engagement_id: str, target: str) -> str:
        rid = f"W-{uuid.uuid4().hex[:12]}"
        now = _now()
        with self._conn() as c:
            c.execute("INSERT INTO runs (id, engagement_id, target, state, status, checkpoint, "
                      "created_at) VALUES (?,?,?,?,?,?,?)",
                      (rid, engagement_id, target, "scope", "running", "{}", now))
            self._event(c, rid, None, "scope", None, "created")
        return rid

    def get(self, run_id: str) -> Optional[Dict]:
        with self._conn() as c:
            row = c.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
            if not row:
                return None
            d = dict(row)
            d["checkpoint"] = json.loads(d.get("checkpoint") or "{}")
            d["history"] = [dict(e) for e in c.execute(
                "SELECT from_state, to_state, approval, note, ts FROM events "
                "WHERE run_id=? ORDER BY ts", (run_id,)).fetchall()]
            return d

    def advance(self, run_id: str, to_state: str, *,
                approver: Optional[Callable[[str], bool]] = None,
                precondition_ok: bool = True, note: str = "") -> Dict:
        """Move forward. Enforces the transition graph, a precondition flag, and —
        for high-consequence target states — an approval callback (returns True to
        allow). Writes a checkpoint event. Raises WorkflowError on any block."""
        with self._conn() as c:
            row = c.execute("SELECT state, status FROM runs WHERE id=?", (run_id,)).fetchone()
            if not row:
                raise WorkflowError(f"unknown workflow {run_id}")
            if row["status"] == "halted":
                raise WorkflowError("workflow is halted — call resume() first")
            frm = row["state"]
            if to_state not in TRANSITIONS.get(frm, set()):
                raise WorkflowError(f"illegal transition {frm} -> {to_state}")
            if not precondition_ok:
                raise WorkflowError(f"precondition for '{to_state}' not met")
            approval = "n/a"
            if to_state in _APPROVAL_REQUIRED:
                if approver is None or not approver(to_state):
                    self._event(c, run_id, frm, to_state, "denied", note)
                    raise WorkflowError(f"approval denied for high-consequence state '{to_state}'")
                approval = "approved"
            status = "done" if to_state == "done" else "running"
            c.execute("UPDATE runs SET state=?, status=?, updated_at=? WHERE id=?",
                      (to_state, status, _now(), run_id))
            self._event(c, run_id, frm, to_state, approval, note)
        return {"id": run_id, "from": frm, "to": to_state, "approval": approval}

    def checkpoint(self, run_id: str, data: Dict) -> Dict:
        """Persist a durable checkpoint snapshot for the current state (for recovery)."""
        with self._conn() as c:
            if not c.execute("SELECT 1 FROM runs WHERE id=?", (run_id,)).fetchone():
                raise WorkflowError(f"unknown workflow {run_id}")
            c.execute("UPDATE runs SET checkpoint=?, updated_at=? WHERE id=?",
                      (json.dumps(data), _now(), run_id))
        return {"id": run_id, "checkpointed": True}

    def halt(self, run_id: str, reason: str = "emergency-stop") -> Dict:
        """Freeze a run at its current state (emergency stop). Resumable."""
        with self._conn() as c:
            row = c.execute("SELECT state FROM runs WHERE id=?", (run_id,)).fetchone()
            if not row:
                raise WorkflowError(f"unknown workflow {run_id}")
            c.execute("UPDATE runs SET status='halted', updated_at=? WHERE id=?", (_now(), run_id))
            self._event(c, run_id, row["state"], row["state"], None, f"halted: {reason}")
        return {"id": run_id, "status": "halted", "state": row["state"]}

    def resume(self, run_id: str) -> Dict:
        """Recover a halted run: flip back to running at the last checkpointed state."""
        with self._conn() as c:
            row = c.execute("SELECT state, status, checkpoint FROM runs WHERE id=?",
                            (run_id,)).fetchone()
            if not row:
                raise WorkflowError(f"unknown workflow {run_id}")
            c.execute("UPDATE runs SET status='running', updated_at=? WHERE id=?", (_now(), run_id))
            self._event(c, run_id, row["state"], row["state"], None, "resumed")
        return {"id": run_id, "status": "running", "state": row["state"],
                "checkpoint": json.loads(row["checkpoint"] or "{}")}

    def list_runs(self, status: str = "") -> List[Dict]:
        q, args = "SELECT id, engagement_id, target, state, status FROM runs", []
        if status:
            q += " WHERE status=?"
            args.append(status)
        with self._conn() as c:
            return [dict(r) for r in c.execute(q + " ORDER BY created_at", args).fetchall()]

    def _event(self, c, run_id, frm, to, approval, note) -> None:
        c.execute("INSERT INTO events (id, run_id, from_state, to_state, approval, note, ts) "
                  "VALUES (?,?,?,?,?,?,?)",
                  (f"EV-{uuid.uuid4().hex[:10]}", run_id, frm, to, approval, note, _now()))


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time()))
