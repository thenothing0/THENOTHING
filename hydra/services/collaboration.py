"""Multi-Agent Collaboration Service (Phase 10.4).

Enables specialized agents to collaborate on complex targets.
Agents share findings, divide work, and cross-validate results
through a structured collaboration protocol.
"""

import logging
import time
from typing import Any

from hydra.services.base import BaseService

logger = logging.getLogger("hydra.services.collaboration")

COLLABORATION_ROLES = (
    "coordinator", "scanner", "analyzer", "validator",
    "exploiter", "reporter", "observer",
)

TASK_STATES = ("pending", "assigned", "in_progress", "completed", "failed")


class CollaborationTask:
    __slots__ = (
        "id", "description", "role", "state", "agent_id",
        "target", "result", "created_at", "completed_at",
    )

    def __init__(self, description: str, role: str = "scanner",
                 target: str = "", agent_id: str = ""):
        self.id = f"ct-{int(time.time() * 1000)}"
        self.description = description
        self.role = role
        self.state = "pending"
        self.agent_id = agent_id
        self.target = target
        self.result: dict | None = None
        self.created_at = time.time()
        self.completed_at: float | None = None

    def to_dict(self) -> dict:
        return {
            "id": self.id, "description": self.description,
            "role": self.role, "state": self.state,
            "agent_id": self.agent_id, "target": self.target,
            "has_result": self.result is not None,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
        }


class CollaborationService(BaseService):
    """Multi-agent collaboration and task coordination."""

    def __init__(self, event_bus, data_dir=None):
        super().__init__(event_bus, data_dir)
        self._tasks: dict[str, CollaborationTask] = {}
        self._shared_findings: list[dict] = []

    def create_task(self, description: str, role: str = "scanner",
                    target: str = "", agent_id: str = "") -> dict:
        """Create a collaboration task."""
        if role not in COLLABORATION_ROLES:
            return {"status": "error", "error": f"Unknown role: {role}"}
        task = CollaborationTask(description, role, target, agent_id)
        if agent_id:
            task.state = "assigned"
        self._tasks[task.id] = task

        self._emit("collaboration.task_created", {
            "task_id": task.id, "role": role, "target": target,
        })
        return {"status": "created", **task.to_dict()}

    def complete_task(self, task_id: str, result: dict) -> dict:
        """Mark a task as completed with results."""
        task = self._tasks.get(task_id)
        if not task:
            return {"status": "error", "error": "Task not found"}
        task.state = "completed"
        task.result = result
        task.completed_at = time.time()

        self._emit("collaboration.task_completed", {
            "task_id": task_id, "role": task.role,
        })
        return {"status": "completed", **task.to_dict()}

    def share_finding(self, finding: dict, source_agent: str = "") -> dict:
        """Share a finding with all collaborating agents."""
        entry = {
            "finding": finding,
            "source_agent": source_agent,
            "shared_at": time.time(),
            "validated_by": [],
        }
        self._shared_findings.append(entry)

        self._emit("collaboration.finding_shared", {
            "source_agent": source_agent,
            "finding_count": len(self._shared_findings),
        })
        return {"status": "shared", "total_shared": len(self._shared_findings)}

    def validate_finding(self, index: int, validator_agent: str,
                         confirmed: bool) -> dict:
        """Cross-validate a shared finding."""
        if index < 0 or index >= len(self._shared_findings):
            return {"status": "error", "error": "Finding index out of range"}
        entry = self._shared_findings[index]
        entry["validated_by"].append({
            "agent": validator_agent,
            "confirmed": confirmed,
            "validated_at": time.time(),
        })
        return {
            "status": "validated",
            "validations": len(entry["validated_by"]),
            "confirmed_count": sum(1 for v in entry["validated_by"] if v["confirmed"]),
        }

    def list_tasks(self, state: str = "", role: str = "") -> list[dict]:
        """List collaboration tasks."""
        results = []
        for t in self._tasks.values():
            if state and t.state != state:
                continue
            if role and t.role != role:
                continue
            results.append(t.to_dict())
        return results

    def get_shared_findings(self) -> list[dict]:
        """Get all shared findings."""
        return self._shared_findings

    def get_stats(self) -> dict[str, Any]:
        by_state: dict[str, int] = {}
        by_role: dict[str, int] = {}
        for t in self._tasks.values():
            by_state[t.state] = by_state.get(t.state, 0) + 1
            by_role[t.role] = by_role.get(t.role, 0) + 1
        return {
            "total_tasks": len(self._tasks),
            "by_state": by_state,
            "by_role": by_role,
            "shared_findings": len(self._shared_findings),
            "roles": list(COLLABORATION_ROLES),
            "task_states": list(TASK_STATES),
        }
