"""AgentManager — creates, tracks and monitors the team's agents.

Owns the :class:`AgentInfo` registry and per-agent lifecycle (spawn / assign /
start / complete / wait / destroy). Emits additive ``team.agent.*`` events. It
NEVER executes commands — it only tracks state; execution belongs to the
specialists via the coordinator/dispatcher.
"""

from __future__ import annotations

import threading
from collections import defaultdict

from hydra.multi_agent.models import AgentInfo, AgentRole, AgentStatus


class AgentManager:
    """Thread-safe registry + lifecycle for the agent team."""

    def __init__(self, event_bus=None):
        self._lock = threading.RLock()
        self._agents: dict[str, AgentInfo] = {}
        self._instances: dict[str, object] = {}
        self._counters: dict[AgentRole, int] = defaultdict(int)
        self._bus = event_bus

    # ── Creation / destruction ──

    def create(self, role: AgentRole, instance: object | None = None) -> AgentInfo:
        with self._lock:
            self._counters[role] += 1
            agent_id = f"{role.value}-{self._counters[role]}"
            info = AgentInfo(agent_id=agent_id, role=role)
            self._agents[agent_id] = info
            if instance is not None:
                self._instances[agent_id] = instance
        self._emit("team.agent.spawned", {"agent_id": agent_id, "role": role.value})
        return info

    def ensure_roles(self, roles) -> dict[AgentRole, AgentInfo]:
        """Ensure at least one agent exists per requested role."""
        result: dict[AgentRole, AgentInfo] = {}
        for role in roles:
            existing = self.by_role(role)
            result[role] = existing[0] if existing else self.create(role)
        return result

    def destroy(self, agent_id: str) -> None:
        with self._lock:
            self._agents.pop(agent_id, None)
            self._instances.pop(agent_id, None)

    # ── Queries ──

    def get(self, agent_id: str) -> AgentInfo | None:
        with self._lock:
            return self._agents.get(agent_id)

    def instance(self, agent_id: str) -> object | None:
        with self._lock:
            return self._instances.get(agent_id)

    def by_role(self, role: AgentRole) -> list[AgentInfo]:
        with self._lock:
            return [i for i in self._agents.values() if i.role == role]

    def all(self) -> list[AgentInfo]:
        with self._lock:
            return list(self._agents.values())

    # ── Lifecycle transitions ──

    def assign(self, agent_id: str, task_id: str) -> None:
        with self._lock:
            info = self._agents.get(agent_id)
            if info:
                info.status = AgentStatus.BUSY
                info.current_task_id = task_id
        self._emit("team.agent.assigned", {"agent_id": agent_id, "task_id": task_id})

    def start(self, agent_id: str) -> None:
        self._emit("team.agent.started", {"agent_id": agent_id})

    def complete(self, agent_id: str, ok: bool = True) -> None:
        with self._lock:
            info = self._agents.get(agent_id)
            if info:
                info.status = AgentStatus.IDLE
                info.current_task_id = ""
                if ok:
                    info.completed += 1
                else:
                    info.failed += 1
        self._emit("team.agent.completed" if ok else "team.agent.failed",
                   {"agent_id": agent_id})

    def waiting(self, agent_id: str) -> None:
        with self._lock:
            info = self._agents.get(agent_id)
            if info:
                info.status = AgentStatus.WAITING
        self._emit("team.agent.waiting", {"agent_id": agent_id})

    def set_status(self, agent_id: str, status: AgentStatus) -> None:
        with self._lock:
            info = self._agents.get(agent_id)
            if info:
                info.status = status

    # ── Monitoring ──

    def monitor(self) -> list[dict]:
        with self._lock:
            return [i.to_dict() for i in self._agents.values()]

    def status(self) -> dict:
        with self._lock:
            infos = list(self._agents.values())
        by_role: dict[str, int] = {}
        busy = 0
        for info in infos:
            by_role[info.role.value] = by_role.get(info.role.value, 0) + 1
            if info.status == AgentStatus.BUSY:
                busy += 1
        return {"agents": len(infos), "busy": busy, "by_role": by_role}

    def _emit(self, event_type: str, payload: dict) -> None:
        if self._bus is None:
            return
        try:
            self._bus.emit(event_type, payload, source="AgentManager")
        except Exception:
            pass
