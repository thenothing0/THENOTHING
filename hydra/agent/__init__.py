"""HYDRA Autonomous Agent Engine.

An additive planning layer *above* the existing HYDRA backend. The agent decides
which existing HYDRA commands to run and executes them ONLY through
``HydraFacade.execute_command()``. It never bypasses HYDRA, never modifies the
backend architecture, and adds no third-party dependencies.

Public surface is built up across implementation batches; import submodules
directly (e.g. ``from hydra.agent.planner import Planner``) to avoid import-time
coupling between batches.
"""

from __future__ import annotations

from hydra.agent.context import AgentContext, ContextBuilder
from hydra.agent.executor import Executor
from hydra.agent.goals import GoalTracker
from hydra.agent.memory import AgentMemory
from hydra.agent.models import (
    AgentState,
    ExecutionPlan,
    Goal,
    Observation,
    ReasoningStep,
    Reflection,
    ReflectionAction,
    SubTask,
    Task,
    TaskState,
)
from hydra.agent.orchestrator import Orchestrator
from hydra.agent.planner import Planner
from hydra.agent.reasoner import Reasoner
from hydra.agent.reflection import ReflectionEngine
from hydra.agent.scheduler import Scheduler
from hydra.agent.service import AgentService
from hydra.agent.session import AgentSession
from hydra.agent.state import AgentStateMachine

__all__ = [
    "AgentContext",
    "AgentMemory",
    "AgentService",
    "AgentSession",
    "AgentState",
    "AgentStateMachine",
    "ContextBuilder",
    "ExecutionPlan",
    "Executor",
    "Goal",
    "GoalTracker",
    "Observation",
    "Orchestrator",
    "Planner",
    "Reasoner",
    "ReasoningStep",
    "Reflection",
    "ReflectionAction",
    "ReflectionEngine",
    "Scheduler",
    "SubTask",
    "Task",
    "TaskState",
]
