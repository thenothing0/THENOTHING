"""TaskQueue — thread-safe, dependency-aware, priority task queue.

States: READY / ASSIGNED / RUNNING / WAITING / FAILED / COMPLETED / CANCELLED.
Dependency readiness (a task becomes READY when all deps are COMPLETED), priority
scheduling, retries (via re-queue), cancellation, and a bounded task cap. Event-
driven: emits ``team.queue.updated`` on change; no polling loops.
"""

from __future__ import annotations

import threading

from hydra.multi_agent.models import AgentRole, AgentTask, MTaskState

MAX_TASKS = 1000


class TaskQueue:
    """A shared, thread-safe queue of AgentTasks."""

    def __init__(self, event_bus=None, max_tasks: int = MAX_TASKS):
        self._tasks: dict[str, AgentTask] = {}
        self._order: list[str] = []
        self._lock = threading.RLock()
        self._bus = event_bus
        self._max = max_tasks

    # ── Mutation ──

    def add(self, task: AgentTask) -> None:
        with self._lock:
            if task.id not in self._tasks:
                self._order.append(task.id)
            self._tasks[task.id] = task
            self._evict_locked()
        self._refresh()
        self._emit_updated()

    def add_many(self, tasks: list[AgentTask]) -> None:
        with self._lock:
            for task in tasks:
                if task.id not in self._tasks:
                    self._order.append(task.id)
                self._tasks[task.id] = task
            self._evict_locked()
        self._refresh()
        self._emit_updated()

    def mark(self, task: AgentTask, state: MTaskState) -> None:
        with self._lock:
            task.state = state
        self._refresh()
        self._emit_updated()

    def assign(self, task: AgentTask, agent_id: str) -> None:
        with self._lock:
            task.assigned_to = agent_id
            task.state = MTaskState.ASSIGNED
        self._emit_updated()

    def requeue(self, task: AgentTask) -> None:
        """Return a failed task to the pool for another attempt."""
        with self._lock:
            task.error = ""
            task.assigned_to = ""
            task.state = MTaskState.WAITING
        self._refresh()
        self._emit_updated()

    def cancel_all(self) -> None:
        with self._lock:
            for task in self._tasks.values():
                if not task.is_terminal:
                    task.state = MTaskState.CANCELLED
        self._emit_updated()

    # ── Queries ──

    def get(self, task_id: str) -> AgentTask | None:
        with self._lock:
            return self._tasks.get(task_id)

    def all(self) -> list[AgentTask]:
        with self._lock:
            return [self._tasks[tid] for tid in self._order if tid in self._tasks]

    def ready(self, role: AgentRole | None = None) -> list[AgentTask]:
        self._refresh()
        with self._lock:
            tasks = [t for t in self._tasks.values() if t.state == MTaskState.READY]
        if role is not None:
            tasks = [t for t in tasks if t.role == role]
        return sorted(tasks, key=lambda t: t.priority, reverse=True)

    def next_ready(self, role: AgentRole | None = None) -> AgentTask | None:
        ready = self.ready(role)
        return ready[0] if ready else None

    def all_terminal(self) -> bool:
        with self._lock:
            tasks = list(self._tasks.values())
        return bool(tasks) and all(t.is_terminal for t in tasks)

    def is_stuck(self) -> bool:
        self._refresh()
        with self._lock:
            pending = [t for t in self._tasks.values() if not t.is_terminal]
            active = [t for t in pending
                      if t.state in (MTaskState.READY, MTaskState.ASSIGNED, MTaskState.RUNNING)]
        return bool(pending) and not active

    def counts(self) -> dict[str, int]:
        with self._lock:
            result: dict[str, int] = {}
            for task in self._tasks.values():
                result[task.state.value] = result.get(task.state.value, 0) + 1
            return result

    def depth(self) -> int:
        with self._lock:
            return sum(1 for t in self._tasks.values() if not t.is_terminal)

    def snapshot(self) -> dict:
        return {
            "total": len(self.all()),
            "depth": self.depth(),
            "by_state": self.counts(),
        }

    # ── Internals ──

    def _refresh(self) -> None:
        with self._lock:
            done = {tid for tid, t in self._tasks.items()
                    if t.state == MTaskState.COMPLETED}
            for task in self._tasks.values():
                if task.state == MTaskState.WAITING and all(d in done for d in task.depends_on):
                    task.state = MTaskState.READY

    def _evict_locked(self) -> None:
        while len(self._order) > self._max:
            for i, tid in enumerate(self._order):
                task = self._tasks.get(tid)
                if task is None or task.is_terminal:
                    self._order.pop(i)
                    self._tasks.pop(tid, None)
                    break
            else:
                # nothing terminal to evict; drop the oldest regardless
                oldest = self._order.pop(0)
                self._tasks.pop(oldest, None)

    def _emit_updated(self) -> None:
        if self._bus is None:
            return
        try:
            self._bus.emit("team.queue.updated", self.snapshot(), source="TaskQueue")
        except Exception:
            pass
