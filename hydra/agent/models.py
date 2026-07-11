"""Data models for the autonomous agent engine.

Pure, typed, serializable data — no logic, no I/O, no service calls. Every model
round-trips through ``to_dict``/``from_dict`` so sessions can be persisted and
resumed with the existing HYDRA persistence.

The agent NEVER bypasses HYDRA: a ``Task`` carries a raw command string that is
executed only through ``HydraFacade.execute_command()``.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


class TaskState(str, Enum):
    """Lifecycle of a single scheduled task."""

    READY = "ready"
    WAITING = "waiting"
    RUNNING = "running"
    FAILED = "failed"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class AgentState(str, Enum):
    """Lifecycle of the agent as a whole."""

    IDLE = "idle"
    PLANNING = "planning"
    EXECUTING = "executing"
    WAITING = "waiting"
    REFLECTING = "reflecting"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ReflectionAction(str, Enum):
    """What the reflection engine recommends after a task."""

    RETRY = "retry"
    ALTERNATIVE = "alternative"
    CONTINUE = "continue"
    ABORT = "abort"


TERMINAL_TASK_STATES = frozenset(
    {TaskState.COMPLETED, TaskState.FAILED, TaskState.CANCELLED}
)
TERMINAL_AGENT_STATES = frozenset(
    {AgentState.COMPLETED, AgentState.FAILED, AgentState.CANCELLED}
)


@dataclass
class SubTask:
    """A leaf unit of work carrying a raw HYDRA command string."""

    description: str
    command: str
    id: str = field(default_factory=lambda: _new_id("sub"))
    state: TaskState = TaskState.READY
    result: Any = None
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "description": self.description,
            "command": self.command,
            "state": self.state.value,
            "result": self.result,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SubTask:
        return cls(
            description=data.get("description", ""),
            command=data.get("command", ""),
            id=data.get("id", _new_id("sub")),
            state=TaskState(data.get("state", "ready")),
            result=data.get("result"),
            error=data.get("error", ""),
        )


@dataclass
class Task:
    """A planned unit of work with dependencies, priority and confidence."""

    description: str
    command: str = ""
    id: str = field(default_factory=lambda: _new_id("task"))
    depends_on: list[str] = field(default_factory=list)
    priority: int = 5
    confidence: float = 0.5
    state: TaskState = TaskState.WAITING
    attempts: int = 0
    max_attempts: int = 3
    parallel_safe: bool = False
    result: Any = None
    error: str = ""
    subtasks: list[SubTask] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    @property
    def is_terminal(self) -> bool:
        return self.state in TERMINAL_TASK_STATES

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "description": self.description,
            "command": self.command,
            "depends_on": list(self.depends_on),
            "priority": self.priority,
            "confidence": self.confidence,
            "state": self.state.value,
            "attempts": self.attempts,
            "max_attempts": self.max_attempts,
            "parallel_safe": self.parallel_safe,
            "result": self.result,
            "error": self.error,
            "subtasks": [s.to_dict() for s in self.subtasks],
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Task:
        return cls(
            description=data.get("description", ""),
            command=data.get("command", ""),
            id=data.get("id", _new_id("task")),
            depends_on=list(data.get("depends_on", [])),
            priority=int(data.get("priority", 5)),
            confidence=float(data.get("confidence", 0.5)),
            state=TaskState(data.get("state", "waiting")),
            attempts=int(data.get("attempts", 0)),
            max_attempts=int(data.get("max_attempts", 3)),
            parallel_safe=bool(data.get("parallel_safe", False)),
            result=data.get("result"),
            error=data.get("error", ""),
            subtasks=[SubTask.from_dict(s) for s in data.get("subtasks", [])],
            created_at=float(data.get("created_at", time.time())),
        )


@dataclass
class Goal:
    """A high-level objective decomposed into tasks."""

    objective: str
    id: str = field(default_factory=lambda: _new_id("goal"))
    target: str = ""
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "objective": self.objective,
            "target": self.target,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Goal:
        return cls(
            objective=data.get("objective", ""),
            id=data.get("id", _new_id("goal")),
            target=data.get("target", ""),
            created_at=float(data.get("created_at", time.time())),
        )


@dataclass
class ExecutionPlan:
    """An ordered set of tasks plus stop conditions for a goal."""

    goal: Goal
    tasks: list[Task] = field(default_factory=list)
    id: str = field(default_factory=lambda: _new_id("plan"))
    stop_conditions: list[str] = field(default_factory=list)
    revision: int = 0
    created_at: float = field(default_factory=time.time)

    def task_by_id(self, task_id: str) -> Task | None:
        for task in self.tasks:
            if task.id == task_id:
                return task
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "goal": self.goal.to_dict(),
            "tasks": [t.to_dict() for t in self.tasks],
            "stop_conditions": list(self.stop_conditions),
            "revision": self.revision,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ExecutionPlan:
        return cls(
            goal=Goal.from_dict(data.get("goal", {})),
            tasks=[Task.from_dict(t) for t in data.get("tasks", [])],
            id=data.get("id", _new_id("plan")),
            stop_conditions=list(data.get("stop_conditions", [])),
            revision=int(data.get("revision", 0)),
            created_at=float(data.get("created_at", time.time())),
        )


@dataclass
class Observation:
    """A real datum observed from a HYDRA output (never fabricated)."""

    source: str
    data: Any
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {"source": self.source, "data": self.data, "timestamp": self.timestamp}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Observation:
        return cls(
            source=data.get("source", ""),
            data=data.get("data"),
            timestamp=float(data.get("timestamp", time.time())),
        )


@dataclass
class ReasoningStep:
    """One entry in the reasoning stream — a thought over real observations."""

    phase: str
    thought: str
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {"phase": self.phase, "thought": self.thought, "timestamp": self.timestamp}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ReasoningStep:
        return cls(
            phase=data.get("phase", ""),
            thought=data.get("thought", ""),
            timestamp=float(data.get("timestamp", time.time())),
        )


@dataclass
class Reflection:
    """The reflection engine's verdict on a completed/failed task."""

    task_id: str
    success: bool
    action: ReflectionAction
    reason: str = ""
    missing_info: bool = False
    unexpected: bool = False
    alternative_command: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "success": self.success,
            "action": self.action.value,
            "reason": self.reason,
            "missing_info": self.missing_info,
            "unexpected": self.unexpected,
            "alternative_command": self.alternative_command,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Reflection:
        return cls(
            task_id=data.get("task_id", ""),
            success=bool(data.get("success", False)),
            action=ReflectionAction(data.get("action", "continue")),
            reason=data.get("reason", ""),
            missing_info=bool(data.get("missing_info", False)),
            unexpected=bool(data.get("unexpected", False)),
            alternative_command=data.get("alternative_command", ""),
            timestamp=float(data.get("timestamp", time.time())),
        )
