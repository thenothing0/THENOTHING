"""AgentService — the ServiceContainer-facing entry to the agent engine.

Registered as ``ServiceContainer.agent_engine`` (a NEW key; it does not touch the
existing swarm ``.agents`` service). It builds an :class:`Orchestrator` per run
with the caller-injected ``execute_command`` callable, tracks sessions (bounded),
persists them for resume, and exposes cancellation + status. It never calls other
services directly and makes no backend changes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from hydra.agent.memory import AgentMemory
from hydra.agent.models import ExecutionPlan, Goal
from hydra.agent.orchestrator import Orchestrator
from hydra.agent.session import AgentSession
from hydra.services.base import BaseService

MAX_SESSIONS = 100


class AgentService(BaseService):
    """Manages autonomous agent sessions over the frozen HYDRA backend."""

    def __init__(self, event_bus, data_dir: Path | None = None):
        super().__init__(event_bus, data_dir)
        self._sessions: dict[str, AgentSession] = {}
        self._orchestrators: dict[str, Orchestrator] = {}

    # ── Running ──

    def create_orchestrator(self, execute_command: Callable[[str], Any],
                            facade: Any = None) -> Orchestrator:
        return Orchestrator(execute_command, self._bus, facade, str(self._data_dir))

    def run(self, objective: str, execute_command: Callable[[str], Any],
            context: Any = None, facade: Any = None) -> AgentSession:
        """Run an objective to completion (blocking; call from a worker thread)."""
        orch = self.create_orchestrator(execute_command, facade)
        session = AgentSession(
            objective=objective,
            plan=ExecutionPlan(goal=Goal(objective=objective)),
            memory=AgentMemory(data_dir=str(self._data_dir)),
        )
        self._register(session, orch)
        self._emit("agent.session.started", {"session_id": session.id, "objective": objective})
        result = orch.run(objective, context=context, session=session)
        self._sessions[result.id] = result
        self.save_session(result)
        self._emit("agent.session.finished",
                   {"session_id": result.id, "status": result.status})
        return result

    def resume(self, session_id: str, execute_command: Callable[[str], Any],
               facade: Any = None) -> AgentSession | None:
        """Load a persisted session and continue its remaining tasks."""
        session = self.get_session(session_id) or self.load_session(session_id)
        if session is None:
            return None
        orch = self.create_orchestrator(execute_command, facade)
        self._register(session, orch)
        result = orch.resume(session)
        self._sessions[result.id] = result
        self.save_session(result)
        return result

    def cancel(self, session_id: str) -> bool:
        orch = self._orchestrators.get(session_id)
        if orch is None:
            return False
        orch.cancel()
        return True

    # ── Queries ──

    def get_session(self, session_id: str) -> AgentSession | None:
        return self._sessions.get(session_id)

    def list_sessions(self) -> list[dict]:
        return [s.summary() for s in self._sessions.values()]

    def status(self, session_id: str) -> dict:
        orch = self._orchestrators.get(session_id)
        if orch is not None:
            return orch.status()
        session = self._sessions.get(session_id)
        return session.summary() if session else {"status": "unknown"}

    def get_stats(self) -> dict[str, Any]:
        active = sum(1 for s in self._sessions.values() if s.status == "running")
        return {"sessions": len(self._sessions), "active": active}

    def get_health(self) -> dict[str, Any]:
        return {"status": "ok", **self.get_stats()}

    # ── Persistence ──

    def _sessions_dir(self) -> Path:
        return Path(self._data_dir) / "agent" / "sessions"

    def save_session(self, session: AgentSession) -> bool:
        try:
            path = self._sessions_dir() / f"{session.id}.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(session.to_dict(), default=str), encoding="utf-8")
            return True
        except Exception:
            return False

    def load_session(self, session_id: str) -> AgentSession | None:
        try:
            path = self._sessions_dir() / f"{session_id}.json"
            if path.exists():
                data = json.loads(path.read_text(encoding="utf-8"))
                return AgentSession.from_dict(data, data_dir=str(self._data_dir))
        except Exception:
            pass
        return None

    # ── Internals ──

    def _register(self, session: AgentSession, orch: Orchestrator) -> None:
        self._sessions[session.id] = session
        self._orchestrators[session.id] = orch
        while len(self._sessions) > MAX_SESSIONS:
            oldest = next(iter(self._sessions))
            self._sessions.pop(oldest, None)
            self._orchestrators.pop(oldest, None)
