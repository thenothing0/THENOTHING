"""Coordinator — the single entry point for a multi-agent run.

Receives an objective, asks the planner to decompose it into role-tagged tasks,
loads the shared queue/memory, spawns the needed specialists, and drives the
collaboration loop: dispatch ready tasks (to the injected Dispatcher, or via the
built-in per-task runner), collect findings, optionally resolve conflicts and
request replanning, until the queue is terminal, stuck, or cancelled.

Execution of every task flows ONLY through the injected ``execute_command``.
"""

from __future__ import annotations

import threading
from typing import Any, Callable

from hydra.multi_agent.manager import AgentManager
from hydra.multi_agent.models import AgentRole, AgentTask, MTaskState
from hydra.multi_agent.planner_agent import PlannerAgent, build_task_plan
from hydra.multi_agent.shared_memory import SharedMemory
from hydra.multi_agent.task_queue import TaskQueue
from hydra.observability.telemetry import telemetry

MAX_ITERATIONS = 300


class Coordinator:
    """Coordinates the specialist team to achieve an objective."""

    def __init__(
        self,
        execute_command: Callable[[str], Any],
        event_bus=None,
        facade: Any = None,
        manager: AgentManager | None = None,
        queue: TaskQueue | None = None,
        memory: SharedMemory | None = None,
        planner: PlannerAgent | None = None,
        dispatcher: Any = None,
        conflict_resolver: Any = None,
        max_iterations: int = MAX_ITERATIONS,
    ):
        self._execute = execute_command
        self._bus = event_bus
        self._facade = facade
        self.manager = manager or AgentManager(event_bus)
        self.queue = queue or TaskQueue(event_bus)
        self.memory = memory or SharedMemory()
        self._planner = planner or PlannerAgent()
        self._dispatcher = dispatcher
        self._conflict = conflict_resolver
        self._maxit = max(1, max_iterations)
        self._cancel = threading.Event()
        self._max_retries = 1

    # ── Control ──

    def cancel(self) -> None:
        self._cancel.set()
        if self._dispatcher is not None and hasattr(self._dispatcher, "cancel"):
            self._dispatcher.cancel()

    def set_max_iterations(self, value: int) -> None:
        self._maxit = max(1, value)

    def status(self) -> dict:
        return {
            "queue": self.queue.snapshot(),
            "agents": self.manager.status(),
            "memory": self.memory.summary(),
        }

    # ── Planning ──

    def plan(self, objective: str) -> list[AgentTask]:
        try:
            return self._planner.plan(objective)
        except Exception:
            return build_task_plan(objective)

    # ── Main collaboration loop ──

    def run(self, objective: str) -> dict:
        self._cancel.clear()
        from hydra.agent import prompts
        target = prompts.extract_target(objective)
        self.memory.set_goal(objective, target)

        tasks = self.plan(objective)
        self.queue.add_many(tasks)
        self.manager.ensure_roles({t.role for t in tasks} | {AgentRole.COORDINATOR})

        iterations = 0
        while iterations < self._maxit:
            iterations += 1
            if self._cancel.is_set():
                break
            ready = self.queue.ready()
            if not ready:
                break
            self._dispatch(ready)
            if self._conflict is not None:
                try:
                    self._conflict.resolve(self.memory)
                except Exception:
                    pass
            self._emit_progress()
            if self.queue.all_terminal() or self.queue.is_stuck():
                break

        return self._finalize()

    def _dispatch(self, ready: list[AgentTask]) -> None:
        if self._dispatcher is not None:
            self._dispatcher.dispatch(ready)
        else:
            for task in ready:
                if self._cancel.is_set():
                    break
                self.execute_task(task)

    # ── Single-task primitive (reused by the Dispatcher) ──

    def execute_task(self, task: AgentTask) -> Any:
        if self._cancel.is_set():
            self.queue.mark(task, MTaskState.CANCELLED)
            return None
        agent = self._agent_for(task.role)
        self.queue.assign(task, agent)
        self.manager.assign(agent, task.id)
        self.manager.start(agent)
        self.queue.mark(task, MTaskState.RUNNING)

        last: Any = None
        ok = False
        for _ in range(1 + self._max_retries):
            if self._cancel.is_set():
                self.queue.mark(task, MTaskState.CANCELLED)
                self.manager.complete(agent, ok=False)
                return last
            task.attempts += 1
            with telemetry.timer("team.task"):
                ok, last = self._attempt(task.command)
            if ok:
                break
        if ok:
            task.result = last
            task.error = ""
            self.queue.mark(task, MTaskState.COMPLETED)
            self._extract_findings(task, last)
            self.manager.complete(agent, ok=True)
            telemetry.counter("team.task.success")
        else:
            task.error = self._error_text(last)
            self.queue.mark(task, MTaskState.FAILED)
            self.manager.complete(agent, ok=False)
            telemetry.counter("team.task.failure")

        self.memory.record_execution(agent, task.command, task.state.value, task.error)
        self.memory.record_output(agent, task.id, task.result)
        telemetry.counter("team.commands")
        return last

    # ── Helpers ──

    def _agent_for(self, role: AgentRole) -> str:
        infos = self.manager.by_role(role)
        if not infos:
            infos = [self.manager.create(role)]
        return infos[0].agent_id

    def _attempt(self, command: str) -> tuple[bool, Any]:
        try:
            value = self._execute(command)
        except Exception as exc:
            return False, {"error": str(exc)}
        if getattr(value, "status", None) == "error":
            return False, value
        if isinstance(value, dict) and value.get("error"):
            return False, value
        return True, value

    def _extract_findings(self, task: AgentTask, value: Any) -> None:
        confirmed = None
        if isinstance(value, dict):
            confirmed = value.get("confirmed_findings") or value.get("confirmed")
        elif getattr(value, "output", None) and isinstance(value.output, dict):
            confirmed = value.output.get("confirmed_findings")
        if not confirmed:
            return
        from hydra.multi_agent.models import Finding
        parts = task.command.split()
        vuln = parts[2] if task.command.startswith("/scan") and len(parts) > 2 else ""
        for item in confirmed[:20]:
            title = item.get("title", item.get("id", "finding")) if isinstance(item, dict) else str(item)
            self.memory.add_finding(Finding(
                title=title, source=task.role.value, vuln_class=vuln,
                target=self.memory.target, confidence=task.confidence,
                data=item if isinstance(item, dict) else {}))

    @staticmethod
    def _error_text(value: Any) -> str:
        errors = getattr(value, "errors", None)
        if errors:
            return "; ".join(str(e) for e in errors)
        if isinstance(value, dict) and value.get("error"):
            return str(value["error"])
        return "task failed"

    def _emit_progress(self) -> None:
        if self._bus is None:
            return
        try:
            self._bus.emit("team.goal.progress", self.status(), source="Coordinator")
        except Exception:
            pass

    def _finalize(self) -> dict:
        if self._cancel.is_set():
            self.queue.cancel_all()
            status = "cancelled"
        else:
            failed = [t for t in self.queue.all() if t.state == MTaskState.FAILED]
            completed = [t for t in self.queue.all() if t.state == MTaskState.COMPLETED]
            status = "failed" if failed and not completed else "completed"
        return {
            "status": status,
            "tasks": [t.to_dict() for t in self.queue.all()],
            "findings": [f.to_dict() for f in self.memory.findings()],
            "agents": self.manager.monitor(),
            "summary": self.memory.summary(),
        }
