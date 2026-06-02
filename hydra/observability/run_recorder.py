"""
╔══════════════════════════════════════════════════════════════╗
║  RunRecorder — Debug & Replay Harness (Pillar 7)              ║
╚══════════════════════════════════════════════════════════════╝

Why this exists
---------------
Mitigates Risk #2 (the autonomous engine and its live tool-execution
chain were entirely opaque after the fact) and Risk #5 (no record of
which tools ran with which arguments). A red-team run that fires real
security tools against a target MUST be reconstructable — for root-cause
analysis, for evidence chains, and for deterministic replay during
debugging.

What it does
------------
Writes ONE self-contained JSON file per run under ``output/runs/<id>.json``
capturing: target, workflow, planner decisions, the ordered tool-execution
chain (binary + sanitized args + return code + latency + timestamp), and
the final result.

It is intentionally dependency-free (stdlib only) and crash-proof: a
failure to record must never break a live operation. The ``mcp_server``
subprocess boundary appends tool events here via :func:`record_tool_event`,
keyed off the ``HYDRA_RUN_DIR`` / ``HYDRA_RUN_ID`` environment variables so
the recorder and the MCP server stay decoupled.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

# Repo-root/output/runs   (this file: hydra/observability/run_recorder.py)
_DEFAULT_RUN_DIR = Path(__file__).resolve().parents[2] / "output" / "runs"

ENV_RUN_DIR = "HYDRA_RUN_DIR"
ENV_RUN_ID = "HYDRA_RUN_ID"


def _now() -> float:
    return round(time.time(), 3)


def _resolve_run_dir(run_dir: Optional[str | Path]) -> Path:
    if run_dir:
        return Path(run_dir)
    env = os.environ.get(ENV_RUN_DIR)
    return Path(env) if env else _DEFAULT_RUN_DIR


class RunRecorder:
    """Records a single THENOTHING run to a replayable JSON file."""

    def __init__(self, target: str = "", workflow: str = "",
                 run_dir: Optional[str | Path] = None,
                 run_id: Optional[str] = None):
        self.run_dir = _resolve_run_dir(run_dir)
        self.run_id = run_id or f"run-{int(time.time())}-{uuid.uuid4().hex[:6]}"
        self.target = target
        self.workflow = workflow
        self._data: Dict[str, Any] = {
            "run_id": self.run_id,
            "target": target,
            "workflow": workflow,
            "started_at": _now(),
            "ended_at": None,
            "status": "running",
            "events": [],
            "result": None,
        }

    # ── lifecycle ────────────────────────────────────────────
    @property
    def path(self) -> Path:
        return self.run_dir / f"{self.run_id}.json"

    def start_run(self, export_env: bool = True) -> "RunRecorder":
        """Create the run file and (optionally) publish env vars so the
        MCP subprocess boundary can append tool events to THIS run."""
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self._write(self._data)
        if export_env:
            os.environ[ENV_RUN_DIR] = str(self.run_dir)
            os.environ[ENV_RUN_ID] = self.run_id
        return self

    def record_event(self, kind: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        event = {
            "event_id": uuid.uuid4().hex[:12],
            "kind": kind,
            "ts": _now(),
            "data": data or {},
        }
        # The FILE is the source of truth: tool events are appended to it by
        # the MCP boundary (record_tool_event), possibly between our calls.
        # Read-modify-write so we never clobber those.
        cur = self._load()
        cur.setdefault("events", []).append(event)
        self._write(cur)
        return event

    def record_planner(self, goal: str, tasks: List[Any]) -> None:
        """Record planner decisions. Accepts HTNTask objects or dicts."""
        decoded = []
        for t in tasks:
            if hasattr(t, "to_dict"):
                decoded.append(t.to_dict())
            elif isinstance(t, dict):
                decoded.append(t)
            else:
                decoded.append({"name": getattr(t, "name", str(t)),
                                "agent": getattr(t, "agent_type", "")})
        self.record_event("planner", {"goal": goal, "tasks": decoded, "count": len(decoded)})

    def finish_run(self, result: Any = None, status: str = "completed") -> Path:
        cur = self._load()
        cur["result"] = result
        cur["status"] = status
        cur["ended_at"] = _now()
        self._write(cur)
        # Clear env so a subsequent run in the same process doesn't bleed in.
        if os.environ.get(ENV_RUN_ID) == self.run_id:
            os.environ.pop(ENV_RUN_DIR, None)
            os.environ.pop(ENV_RUN_ID, None)
        return self.path

    def _load(self) -> Dict[str, Any]:
        """Read the run file (source of truth); fall back to the template."""
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            return dict(self._data)

    def _write(self, data: Dict[str, Any]) -> None:
        try:
            self.run_dir.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception:
            # Recording must never break a live operation.
            pass


# ── Module-level helpers (used by the MCP boundary + replay) ──

def record_tool_event(binary: str, args: List[str], result: Dict[str, Any]) -> None:
    """Append a tool-execution event to the active run file, if one is set.

    Called from ``mcp_server._run``. Best-effort and never raises: if no run
    is active (env not set) or the file is missing, it silently no-ops.
    """
    run_dir = os.environ.get(ENV_RUN_DIR)
    run_id = os.environ.get(ENV_RUN_ID)
    if not run_dir or not run_id:
        return
    path = Path(run_dir) / f"{run_id}.json"
    if not path.exists():
        return
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        data.setdefault("events", []).append({
            "event_id": uuid.uuid4().hex[:12],
            "kind": "tool_exec",
            "ts": _now(),
            "data": {
                "binary": binary,
                # args are already sanitized command tokens (no shell)
                "args": list(args),
                "return_code": result.get("return_code"),
                "success": result.get("success"),
                "elapsed_seconds": result.get("elapsed_seconds"),
                "error": result.get("error"),
            },
        })
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception:
        pass


def load_run(run_id: str, run_dir: Optional[str | Path] = None) -> Dict[str, Any]:
    """Load a recorded run by id."""
    path = _resolve_run_dir(run_dir) / f"{run_id}.json"
    return json.loads(path.read_text(encoding="utf-8"))


def replay(run_id: str, run_dir: Optional[str | Path] = None) -> List[Dict[str, Any]]:
    """Return the ordered event chain of a run for deterministic inspection.

    This is a *deterministic re-read* of what happened — it does not re-execute
    tools (that would be unsafe and non-reproducible). Use it to reconstruct the
    decision/execution chain during root-cause analysis.
    """
    return load_run(run_id, run_dir).get("events", [])
