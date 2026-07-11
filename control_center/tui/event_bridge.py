"""EventBridge — translates HYDRA EventBus events into Textual Messages.

The bridge subscribes to the EventBus (from the PresentationAPI) and posts
Textual messages into the app, so widgets react through Textual's native
message system rather than polling.
"""

from __future__ import annotations

from textual.app import App
from textual.message import Message

from hydra.services.event_bus import Event, EventBus


class HydraEvent(Message):
    """Generic wrapper: carries any EventBus event into Textual."""

    def __init__(self, event: Event):
        super().__init__()
        self.event = event

    @property
    def event_type(self) -> str:
        return self.event.type

    @property
    def payload(self) -> dict:
        return self.event.payload


class ToolStarted(Message):
    def __init__(self, tool: str, target: str = ""):
        super().__init__()
        self.tool = tool
        self.target = target


class ToolCompleted(Message):
    def __init__(self, tool: str, target: str = "", result: dict | None = None):
        super().__init__()
        self.tool = tool
        self.target = target
        self.result = result or {}


class ToolFailed(Message):
    def __init__(self, tool: str, error: str = ""):
        super().__init__()
        self.tool = tool
        self.error = error


class ToolOutputChunk(Message):
    def __init__(self, tool: str, chunk: str):
        super().__init__()
        self.tool = tool
        self.chunk = chunk


class FindingCreated(Message):
    def __init__(self, finding_id: str, severity: str = "info"):
        super().__init__()
        self.finding_id = finding_id
        self.severity = severity


class WorkflowAdvanced(Message):
    def __init__(self, run_id: str, state: str):
        super().__init__()
        self.run_id = run_id
        self.state = state


class AIToken(Message):
    def __init__(self, token: str):
        super().__init__()
        self.token = token


class AIChatCompleted(Message):
    def __init__(self, length: int):
        super().__init__()
        self.length = length


class AgentSpawned(Message):
    def __init__(self, agent_type: str, task_id: str = ""):
        super().__init__()
        self.agent_type = agent_type
        self.task_id = task_id


class AgentTaskCompleted(Message):
    def __init__(self, agent_type: str, status: str = "completed"):
        super().__init__()
        self.agent_type = agent_type
        self.status = status


class FindingTransitioned(Message):
    def __init__(self, finding_id: str, to_state: str = ""):
        super().__init__()
        self.finding_id = finding_id
        self.to_state = to_state


# ── Autonomous Agent Engine messages ──

class AgentStarted(Message):
    def __init__(self, objective: str, target: str = "", session_id: str = ""):
        super().__init__()
        self.objective = objective
        self.target = target
        self.session_id = session_id


class AgentPlanReady(Message):
    def __init__(self, session_id: str, tasks: int = 0, revision: int = 0):
        super().__init__()
        self.session_id = session_id
        self.tasks = tasks
        self.revision = revision


class AgentReasoning(Message):
    def __init__(self, phase: str, thought: str):
        super().__init__()
        self.phase = phase
        self.thought = thought


class AgentGoalProgress(Message):
    def __init__(self, payload: dict):
        super().__init__()
        self.payload = payload


class AgentTaskUpdate(Message):
    def __init__(self, state: str, command: str = "", description: str = ""):
        super().__init__()
        self.state = state
        self.command = command
        self.description = description


class AgentRunFinished(Message):
    def __init__(self, status: str, session_id: str = ""):
        super().__init__()
        self.status = status
        self.session_id = session_id


class EventBridge:
    """Subscribes to EventBus, posts Textual Messages into the app."""

    TYPED_EVENTS = {
        "tool.started": lambda p: ToolStarted(p.get("tool", ""), p.get("target", "")),
        "tool.completed": lambda p: ToolCompleted(p.get("tool", ""), p.get("target", ""), p.get("result")),
        "tool.failed": lambda p: ToolFailed(p.get("tool", ""), p.get("error", "")),
        "tool.output": lambda p: ToolOutputChunk(p.get("tool", ""), p.get("chunk", "")),
        "finding.created": lambda p: FindingCreated(p.get("finding_id", ""), p.get("severity", "info")),
        "workflow.advanced": lambda p: WorkflowAdvanced(p.get("run_id", ""), p.get("state", "")),
        "ai.token": lambda p: AIToken(p.get("token", "")),
        "ai.chat_completed": lambda p: AIChatCompleted(p.get("length", 0)),
        "agent.spawned": lambda p: AgentSpawned(p.get("agent_type", ""), p.get("task_id", "")),
        "agent.task_completed": lambda p: AgentTaskCompleted(p.get("agent_type", ""), p.get("status", "completed")),
        "finding.transitioned": lambda p: FindingTransitioned(p.get("finding_id", ""), p.get("to_state", "")),
        # Autonomous Agent Engine (dotted names, distinct from swarm above)
        "agent.started": lambda p: AgentStarted(p.get("objective", ""), p.get("target", ""), p.get("session_id", "")),
        "agent.plan.created": lambda p: AgentPlanReady(p.get("session_id", ""), p.get("tasks", 0), p.get("revision", 0)),
        "agent.plan.updated": lambda p: AgentPlanReady(p.get("session_id", ""), p.get("tasks", 0), p.get("revision", 0)),
        "agent.reasoning": lambda p: AgentReasoning(p.get("phase", ""), p.get("thought", "")),
        "agent.goal.progress": lambda p: AgentGoalProgress(p),
        "agent.task.started": lambda p: AgentTaskUpdate("started", p.get("command", ""), p.get("description", "")),
        "agent.task.completed": lambda p: AgentTaskUpdate("completed", p.get("command", ""), p.get("description", "")),
        "agent.task.failed": lambda p: AgentTaskUpdate("failed", p.get("command", ""), p.get("description", "")),
        "agent.completed": lambda p: AgentRunFinished(p.get("status", "completed"), p.get("session_id", "")),
        "agent.cancelled": lambda p: AgentRunFinished("cancelled", p.get("session_id", "")),
    }

    def __init__(self, app: App, event_bus: EventBus):
        self._app = app
        self._bus = event_bus
        self._sub_ids: list[str] = []

    def connect(self):
        sid = self._bus.subscribe("*", self._on_event)
        self._sub_ids.append(sid)

    def disconnect(self):
        for sid in self._sub_ids:
            self._bus.unsubscribe(sid)
        self._sub_ids.clear()

    def _on_event(self, event: Event):
        factory = self.TYPED_EVENTS.get(event.type)
        if factory:
            self._app.post_message(factory(event.payload))
        self._app.post_message(HydraEvent(event))
