"""Orchestrator — the single public interface for an autonomous run.

Coordinates planner, executor, scheduler, reasoner, reflection, memory, goal
tracker and the state machine through one bounded Observe→Think→Plan→Execute→
Observe→Reflect loop. Emits ``agent.*`` events and records telemetry. Every
command runs ONLY through the injected ``execute_command`` callable.
"""

from __future__ import annotations

import threading
from typing import Any, Callable

from hydra.agent.context import ContextBuilder
from hydra.agent.executor import Executor
from hydra.agent.goals import GoalTracker
from hydra.agent.memory import AgentMemory
from hydra.agent.models import AgentState, ReflectionAction, TaskState
from hydra.agent.planner import Planner
from hydra.agent.reasoner import Reasoner
from hydra.agent.reflection import ReflectionEngine
from hydra.agent.scheduler import Scheduler
from hydra.agent.session import AgentSession
from hydra.agent.state import AgentStateMachine
from hydra.observability.telemetry import telemetry

MAX_ITERATIONS = 200


class Orchestrator:
    """Drives one autonomous agent run to completion (blocking; run in a worker)."""

    def __init__(
        self,
        execute_command: Callable[[str], Any],
        event_bus=None,
        facade: Any = None,
        data_dir: str = "data",
        planner: Planner | None = None,
        max_iterations: int = MAX_ITERATIONS,
    ):
        self._execute = execute_command
        self._bus = event_bus
        self._facade = facade
        self._data_dir = data_dir
        self._planner = planner or Planner()
        self._reflection = ReflectionEngine(event_bus)
        # One attempt per drive iteration; reflection owns cross-iteration retries.
        self._executor = Executor(execute_command, event_bus, max_retries=0)
        self._sm = AgentStateMachine(event_bus=event_bus)
        self._reasoner = Reasoner(event_bus)
        self._cancel = threading.Event()
        self._maxit = max(1, max_iterations)
        self.session: AgentSession | None = None

    # ── Public control ──

    @property
    def state(self) -> AgentState:
        return self._sm.state

    def cancel(self) -> None:
        self._cancel.set()
        self._executor.cancel()

    def status(self) -> dict[str, Any]:
        if self.session is None:
            return {"state": self._sm.state.value, "status": "idle"}
        tracker = GoalTracker(self.session.plan)
        snap = tracker.snapshot()
        snap.update({"state": self._sm.state.value, "status": self.session.status,
                     "session_id": self.session.id})
        return snap

    # ── Main loop ──

    def run(self, objective: str, context: Any = None,
            session: AgentSession | None = None) -> AgentSession:
        self._cancel.clear()
        self._executor.reset()

        if context is None and self._facade is not None:
            context = ContextBuilder(self._facade).build(objective)

        self._sm.transition(AgentState.PLANNING)
        with telemetry.timer("agent.planning"):
            plan = self._planner.plan(objective, context)

        if session is None:
            session = AgentSession(
                objective=objective, plan=plan,
                memory=AgentMemory(data_dir=self._data_dir), target=plan.goal.target)
        else:
            session.plan = plan
        session.memory.session_id = session.id
        session.status = "running"
        self.session = session

        scheduler = Scheduler(plan, self._bus)
        tracker = GoalTracker(plan)
        self._emit("agent.started", {"session_id": session.id, "objective": objective,
                                     "target": plan.goal.target})
        self._emit("agent.plan.created", {"session_id": session.id,
                                          "tasks": len(plan.tasks),
                                          "revision": plan.revision})
        self._reasoner.think_plan(objective, plan.goal.target, len(plan.tasks))

        self._sm.transition(AgentState.EXECUTING)
        return self._drive(session, scheduler, tracker, context)

    def resume(self, session: AgentSession, context: Any = None) -> AgentSession:
        """Continue a persisted session without replanning."""
        self._cancel.clear()
        self._executor.reset()
        session.status = "running"
        self.session = session
        scheduler = Scheduler(session.plan, self._bus)
        scheduler.refresh()
        tracker = GoalTracker(session.plan)
        self._sm.force(AgentState.EXECUTING)
        self._emit("agent.resumed", {"session_id": session.id})
        return self._drive(session, scheduler, tracker, context)

    def _drive(self, session: AgentSession, scheduler: Scheduler,
               tracker: GoalTracker, context: Any) -> AgentSession:
        iterations = 0
        while iterations < self._maxit:
            iterations += 1
            if self._cancel.is_set():
                break
            task = scheduler.next_task()
            if task is None:
                break

            self._reasoner.think_execute(task.command)
            with telemetry.timer("agent.execution"):
                self._executor.execute_task(task)
            session.memory.record_execution(task.id, task.command, task.state.value, task.error)
            telemetry.counter("agent.commands")

            with telemetry.timer("agent.reasoning"):
                self._reasoner.observe(task.command, task.result)

            self._sm.transition(AgentState.REFLECTING)
            with telemetry.timer("agent.reflection"):
                reflection = self._reflection.reflect(task, task.result)
            self._reasoner.think_reflect(task.description, reflection.success,
                                        reflection.action.value)
            telemetry.counter("agent.task.success" if reflection.success
                              else "agent.task.failure")

            if reflection.action in (ReflectionAction.RETRY, ReflectionAction.ALTERNATIVE,
                                     ReflectionAction.ABORT):
                self._sm.transition(AgentState.PLANNING)
                self._planner.replan(session.plan, [reflection], context)
                self._emit("agent.plan.updated", {"session_id": session.id,
                                                  "revision": session.plan.revision})

            session.reasoning_steps = self._reasoner.steps()
            session.touch()
            self._emit("agent.goal.progress", {**tracker.snapshot(), "session_id": session.id})
            session.memory.save()

            if scheduler.all_terminal():
                break
            if self._cancel.is_set():
                break
            if self._sm.state != AgentState.EXECUTING:
                self._sm.transition(AgentState.EXECUTING)

        return self._finalize(session, scheduler, tracker)

    # ── Finalisation ──

    def _finalize(self, session: AgentSession, scheduler: Scheduler,
                  tracker: GoalTracker) -> AgentSession:
        if self._cancel.is_set():
            scheduler.cancel_pending()
            self._finish(AgentState.CANCELLED)
            session.status = "cancelled"
            self._emit("agent.cancelled", {"session_id": session.id})
        else:
            failed = [t for t in session.plan.tasks if t.state == TaskState.FAILED]
            if failed and not tracker.completed():
                self._finish(AgentState.FAILED)
                session.status = "failed"
                session.error = "; ".join(t.error for t in failed if t.error)[:500]
            else:
                self._finish(AgentState.COMPLETED)
                session.status = "completed"
            self._emit("agent.completed", {**tracker.snapshot(), "session_id": session.id,
                                           "status": session.status})
        session.state = self._sm.state
        session.reasoning_steps = self._reasoner.steps()
        session.touch()
        session.memory.save()
        return session

    def _finish(self, state: AgentState) -> None:
        if not self._sm.transition(state):
            self._sm.force(state)

    def set_max_iterations(self, value: int) -> None:
        self._maxit = max(1, value)

    def _emit(self, event_type: str, payload: dict) -> None:
        if self._bus is None:
            return
        try:
            self._bus.emit(event_type, payload, source="Orchestrator")
        except Exception:
            pass
