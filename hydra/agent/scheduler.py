"""Scheduler — dependency-aware task readiness over an ExecutionPlan.

Pure computation, event-driven, no polling loops: given the current task states
it reports which tasks are READY (all dependencies COMPLETED), transitions
WAITING↔READY accordingly, and answers whether the plan is done or stuck. The
orchestrator drives it in response to executor/EventBus events.
"""

from __future__ import annotations

from hydra.agent.models import ExecutionPlan, Task, TaskState


class Scheduler:
    """Computes ready tasks and plan completion from dependency states."""

    def __init__(self, plan: ExecutionPlan, event_bus=None):
        self.plan = plan
        self._bus = event_bus

    # ── Readiness ──

    def _completed_ids(self) -> set[str]:
        return {t.id for t in self.plan.tasks if t.state == TaskState.COMPLETED}

    def refresh(self) -> None:
        """Promote WAITING tasks whose dependencies are all COMPLETED to READY."""
        done = self._completed_ids()
        for task in self.plan.tasks:
            if task.state == TaskState.WAITING and all(d in done for d in task.depends_on):
                task.state = TaskState.READY
                self._emit("agent.task.ready", task)

    def ready_tasks(self) -> list[Task]:
        """Currently-READY tasks, highest priority first."""
        self.refresh()
        ready = [t for t in self.plan.tasks if t.state == TaskState.READY]
        return sorted(ready, key=lambda t: t.priority, reverse=True)

    def next_task(self) -> Task | None:
        ready = self.ready_tasks()
        return ready[0] if ready else None

    def next_parallel_batch(self, limit: int = 4) -> list[Task]:
        """A batch of parallel-safe READY tasks (bounded)."""
        ready = self.ready_tasks()
        batch = [t for t in ready if t.parallel_safe][:max(1, limit)]
        return batch

    # ── State transitions ──

    def mark(self, task: Task, state: TaskState) -> None:
        task.state = state
        self._emit(f"agent.task.{state.value}", task)
        if state == TaskState.COMPLETED:
            self.refresh()

    # ── Completion / stuck detection ──

    def all_terminal(self) -> bool:
        return bool(self.plan.tasks) and all(t.is_terminal for t in self.plan.tasks)

    def has_runnable(self) -> bool:
        """True if any task can still make progress (ready, waiting or running)."""
        self.refresh()
        return any(
            t.state in (TaskState.READY, TaskState.RUNNING, TaskState.WAITING)
            for t in self.plan.tasks
        )

    def is_stuck(self) -> bool:
        """No terminal-completion possible: nothing ready/running but work remains."""
        self.refresh()
        pending = [t for t in self.plan.tasks if not t.is_terminal]
        if not pending:
            return False
        active = [t for t in pending if t.state in (TaskState.READY, TaskState.RUNNING)]
        return not active

    def cancel_pending(self) -> None:
        for task in self.plan.tasks:
            if not task.is_terminal:
                self.mark(task, TaskState.CANCELLED)

    def _emit(self, event_type: str, task: Task) -> None:
        if self._bus is None:
            return
        try:
            self._bus.emit(event_type, {
                "task_id": task.id,
                "description": task.description,
                "command": task.command,
                "state": task.state.value,
            })
        except Exception:
            pass
