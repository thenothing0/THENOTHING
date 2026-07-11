"""AgentSession — the serialisable state of one autonomous run.

Bundles the plan, memory, reasoning trace, agent state and status so a run can
be inspected, persisted and resumed after a restart. Pure data + (de)serialise;
the live helpers (state machine, reasoner, scheduler, executor) are built around
a session by the orchestrator.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from hydra.agent.memory import AgentMemory
from hydra.agent.models import AgentState, ExecutionPlan, Goal, ReasoningStep


def _new_id() -> str:
    return f"sess-{uuid.uuid4().hex[:10]}"


@dataclass
class AgentSession:
    """One autonomous agent run, fully serialisable for resume."""

    objective: str
    plan: ExecutionPlan
    memory: AgentMemory
    id: str = field(default_factory=_new_id)
    target: str = ""
    state: AgentState = AgentState.IDLE
    status: str = "created"
    reasoning_steps: list[ReasoningStep] = field(default_factory=list)
    error: str = ""
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def touch(self) -> None:
        self.updated_at = time.time()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "objective": self.objective,
            "target": self.target,
            "state": self.state.value,
            "status": self.status,
            "error": self.error,
            "plan": self.plan.to_dict(),
            "memory": self.memory.to_dict(),
            "reasoning_steps": [s.to_dict() for s in self.reasoning_steps],
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any], data_dir: str = "data") -> AgentSession:
        plan = ExecutionPlan.from_dict(data.get("plan", {"goal": Goal(objective="").to_dict()}))
        memory = AgentMemory.from_dict(data.get("memory", {}), data_dir=data_dir)
        return cls(
            objective=data.get("objective", ""),
            plan=plan,
            memory=memory,
            id=data.get("id", _new_id()),
            target=data.get("target", ""),
            state=AgentState(data.get("state", "idle")),
            status=data.get("status", "created"),
            error=data.get("error", ""),
            reasoning_steps=[ReasoningStep.from_dict(s) for s in data.get("reasoning_steps", [])],
            created_at=float(data.get("created_at", time.time())),
            updated_at=float(data.get("updated_at", time.time())),
        )

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "objective": self.objective,
            "target": self.target,
            "state": self.state.value,
            "status": self.status,
            "tasks": len(self.plan.tasks),
            "revision": self.plan.revision,
        }
