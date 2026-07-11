"""GoalTracker — read-only progress view over an ExecutionPlan.

Computes completion %, current/completed/remaining/blocked tasks, aggregate
confidence and a rough completion estimate. Pure computation over task states —
no execution, no I/O.
"""

from __future__ import annotations

from typing import Any

from hydra.agent.models import ExecutionPlan, Task, TaskState


class GoalTracker:
    """Derives goal progress from a plan's task states."""

    def __init__(self, plan: ExecutionPlan):
        self.plan = plan

    # ── Task partitions ──

    def completed(self) -> list[Task]:
        return [t for t in self.plan.tasks if t.state == TaskState.COMPLETED]

    def failed(self) -> list[Task]:
        return [t for t in self.plan.tasks if t.state == TaskState.FAILED]

    def remaining(self) -> list[Task]:
        return [t for t in self.plan.tasks if not t.is_terminal]

    def running(self) -> list[Task]:
        return [t for t in self.plan.tasks if t.state == TaskState.RUNNING]

    def blocked(self) -> list[Task]:
        """WAITING tasks with a dependency that failed or was cancelled."""
        bad = {
            t.id for t in self.plan.tasks
            if t.state in (TaskState.FAILED, TaskState.CANCELLED)
        }
        return [
            t for t in self.plan.tasks
            if t.state == TaskState.WAITING and any(dep in bad for dep in t.depends_on)
        ]

    def current_task(self) -> Task | None:
        running = self.running()
        if running:
            return running[0]
        ready = [t for t in self.plan.tasks if t.state == TaskState.READY]
        if ready:
            return max(ready, key=lambda t: t.priority)
        return None

    # ── Scalars ──

    def completion_pct(self) -> float:
        total = len(self.plan.tasks)
        if not total:
            return 0.0
        terminal_done = len(self.completed())
        return round(100.0 * terminal_done / total, 1)

    def is_complete(self) -> bool:
        return all(t.is_terminal for t in self.plan.tasks) and bool(self.plan.tasks)

    def confidence(self) -> float:
        """Aggregate confidence: mean task confidence, penalised by failures."""
        tasks = [t for t in self.plan.tasks if t.state != TaskState.CANCELLED]
        if not tasks:
            return 0.0
        mean_conf = sum(t.confidence for t in tasks) / len(tasks)
        penalty = 0.15 * len(self.failed())
        return round(max(0.0, min(1.0, mean_conf - penalty)), 3)

    def estimated_remaining(self) -> int:
        return len(self.remaining())

    # ── Snapshot for events / UI ──

    def snapshot(self) -> dict[str, Any]:
        current = self.current_task()
        return {
            "goal_id": self.plan.goal.id,
            "objective": self.plan.goal.objective,
            "target": self.plan.goal.target,
            "completion_pct": self.completion_pct(),
            "confidence": self.confidence(),
            "total_tasks": len(self.plan.tasks),
            "completed": len(self.completed()),
            "failed": len(self.failed()),
            "remaining": self.estimated_remaining(),
            "blocked": len(self.blocked()),
            "current_task": current.description if current else "",
            "current_task_id": current.id if current else "",
            "revision": self.plan.revision,
        }
