"""Data models for the multi-agent collaboration engine.

Pure, typed, serialisable data — no logic, no I/O. Mirrors the single-agent
engine's discipline: every model round-trips via ``to_dict``/``from_dict`` so
campaigns can persist and resume through existing HYDRA storage.

Execution still flows ONLY through ``HydraFacade.execute_command()``; these
models just describe the work, the messages between agents, and the findings.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


class MTaskState(str, Enum):
    """Lifecycle of a task in the shared queue."""

    READY = "ready"
    ASSIGNED = "assigned"
    RUNNING = "running"
    WAITING = "waiting"
    FAILED = "failed"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class AgentRole(str, Enum):
    """The specialist roles in the team."""

    COORDINATOR = "coordinator"
    PLANNER = "planner"
    RECON = "recon"
    WEB = "web"
    NETWORK = "network"
    KNOWLEDGE = "knowledge"
    REPORT = "report"


class AgentStatus(str, Enum):
    """Runtime status of an agent."""

    IDLE = "idle"
    BUSY = "busy"
    WAITING = "waiting"
    DONE = "done"
    FAILED = "failed"


class MessageType(str, Enum):
    """Typed internal messages passed on the agent message bus."""

    TASK_REQUEST = "task_request"
    TASK_RESULT = "task_result"
    TASK_FAILED = "task_failed"
    KNOWLEDGE_UPDATE = "knowledge_update"
    PLANNING_UPDATE = "planning_update"
    REASONING_UPDATE = "reasoning_update"
    GOAL_PROGRESS = "goal_progress"


class CampaignStatus(str, Enum):
    """Lifecycle of a long-running campaign."""

    CREATED = "created"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


TERMINAL_TASK_STATES = frozenset(
    {MTaskState.COMPLETED, MTaskState.FAILED, MTaskState.CANCELLED}
)


@dataclass
class AgentTask:
    """A unit of work owned by a specialist role, carrying a real command."""

    description: str
    command: str = ""
    role: AgentRole = AgentRole.RECON
    id: str = field(default_factory=lambda: _new_id("mtask"))
    depends_on: list[str] = field(default_factory=list)
    priority: int = 5
    confidence: float = 0.5
    state: MTaskState = MTaskState.WAITING
    assigned_to: str = ""
    attempts: int = 0
    max_attempts: int = 3
    parallel_safe: bool = False
    result: Any = None
    error: str = ""
    created_at: float = field(default_factory=time.time)

    @property
    def is_terminal(self) -> bool:
        return self.state in TERMINAL_TASK_STATES

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "description": self.description,
            "command": self.command,
            "role": self.role.value,
            "depends_on": list(self.depends_on),
            "priority": self.priority,
            "confidence": self.confidence,
            "state": self.state.value,
            "assigned_to": self.assigned_to,
            "attempts": self.attempts,
            "max_attempts": self.max_attempts,
            "parallel_safe": self.parallel_safe,
            "result": self.result,
            "error": self.error,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AgentTask:
        return cls(
            description=data.get("description", ""),
            command=data.get("command", ""),
            role=AgentRole(data.get("role", "recon")),
            id=data.get("id", _new_id("mtask")),
            depends_on=list(data.get("depends_on", [])),
            priority=int(data.get("priority", 5)),
            confidence=float(data.get("confidence", 0.5)),
            state=MTaskState(data.get("state", "waiting")),
            assigned_to=data.get("assigned_to", ""),
            attempts=int(data.get("attempts", 0)),
            max_attempts=int(data.get("max_attempts", 3)),
            parallel_safe=bool(data.get("parallel_safe", False)),
            result=data.get("result"),
            error=data.get("error", ""),
            created_at=float(data.get("created_at", time.time())),
        )


@dataclass
class Message:
    """A typed message exchanged between agents (internal bus, not EventBus)."""

    type: MessageType
    sender: str
    recipient: str = "*"
    payload: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: _new_id("msg"))
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type.value,
            "sender": self.sender,
            "recipient": self.recipient,
            "payload": dict(self.payload),
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Message:
        return cls(
            type=MessageType(data.get("type", "task_result")),
            sender=data.get("sender", ""),
            recipient=data.get("recipient", "*"),
            payload=dict(data.get("payload", {})),
            id=data.get("id", _new_id("msg")),
            timestamp=float(data.get("timestamp", time.time())),
        )


@dataclass
class Finding:
    """A lightweight finding produced by an agent."""

    title: str
    source: str = ""
    severity: str = "info"
    vuln_class: str = ""
    target: str = ""
    confidence: float = 0.5
    data: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: _new_id("find"))

    def signature(self) -> str:
        """Root-cause signature for conflict/dedup detection."""
        return f"{self.vuln_class}|{self.target}".lower()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "source": self.source,
            "severity": self.severity,
            "vuln_class": self.vuln_class,
            "target": self.target,
            "confidence": self.confidence,
            "data": dict(self.data),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        return cls(
            title=data.get("title", ""),
            source=data.get("source", ""),
            severity=data.get("severity", "info"),
            vuln_class=data.get("vuln_class", ""),
            target=data.get("target", ""),
            confidence=float(data.get("confidence", 0.5)),
            data=dict(data.get("data", {})),
            id=data.get("id", _new_id("find")),
        )


@dataclass
class AgentInfo:
    """Status snapshot for a single agent."""

    agent_id: str
    role: AgentRole
    status: AgentStatus = AgentStatus.IDLE
    current_task_id: str = ""
    completed: int = 0
    failed: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "role": self.role.value,
            "status": self.status.value,
            "current_task_id": self.current_task_id,
            "completed": self.completed,
            "failed": self.failed,
        }


@dataclass
class Campaign:
    """A long-running assessment: goals, tasks, timeline, evidence, reports."""

    objective: str
    target: str = ""
    id: str = field(default_factory=lambda: _new_id("camp"))
    status: CampaignStatus = CampaignStatus.CREATED
    tasks: list[AgentTask] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    timeline: list[dict] = field(default_factory=list)
    reports: list[dict] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def add_event(self, kind: str, detail: str = "") -> None:
        self.timeline.append({"kind": kind, "detail": detail, "at": time.time()})
        self.updated_at = time.time()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "objective": self.objective,
            "target": self.target,
            "status": self.status.value,
            "tasks": [t.to_dict() for t in self.tasks],
            "findings": [f.to_dict() for f in self.findings],
            "timeline": list(self.timeline),
            "reports": list(self.reports),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Campaign:
        return cls(
            objective=data.get("objective", ""),
            target=data.get("target", ""),
            id=data.get("id", _new_id("camp")),
            status=CampaignStatus(data.get("status", "created")),
            tasks=[AgentTask.from_dict(t) for t in data.get("tasks", [])],
            findings=[Finding.from_dict(f) for f in data.get("findings", [])],
            timeline=list(data.get("timeline", [])),
            reports=list(data.get("reports", [])),
            created_at=float(data.get("created_at", time.time())),
            updated_at=float(data.get("updated_at", time.time())),
        )
