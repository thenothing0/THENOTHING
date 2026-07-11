"""ReflectionEngine — evaluates a task outcome and recommends the next move.

After each task it judges success/failure, whether information is missing, and
whether the result was unexpected, then recommends RETRY / ALTERNATIVE /
CONTINUE / ABORT. The planner consumes these to replan. Grounded only in the
task's real state and result.
"""

from __future__ import annotations

from typing import Any

from hydra.agent.models import Reflection, ReflectionAction, Task, TaskState

# Fallback command templates when a task type keeps failing.
_FALLBACKS: dict[str, str] = {
    "/attack": "/scan {target} xss",   # de-escalate a failing campaign to a scan
    "/scan": "/recon {target}",        # gather more before scanning
}


class ReflectionEngine:
    """Judges task outcomes and recommends the next action."""

    def __init__(self, event_bus=None):
        self._bus = event_bus

    def reflect(self, task: Task, result: Any = None) -> Reflection:
        success = task.state == TaskState.COMPLETED
        value = result if result is not None else task.result

        if success:
            missing = self._is_empty(value)
            reflection = Reflection(
                task_id=task.id,
                success=True,
                action=ReflectionAction.CONTINUE,
                reason="Task completed." if not missing else "Completed but result was empty.",
                missing_info=missing,
            )
        elif task.state == TaskState.CANCELLED:
            reflection = Reflection(
                task_id=task.id, success=False, action=ReflectionAction.ABORT,
                reason="Task was cancelled.",
            )
        else:  # FAILED (or non-terminal treated as failure)
            reflection = self._reflect_failure(task)

        self._emit(reflection)
        return reflection

    # ── Failure handling ──

    def _reflect_failure(self, task: Task) -> Reflection:
        if task.attempts < task.max_attempts:
            return Reflection(
                task_id=task.id, success=False, action=ReflectionAction.RETRY,
                reason=f"Failed (attempt {task.attempts}/{task.max_attempts}); retry.",
                unexpected=bool(task.error),
            )
        alt = self._fallback(task.command)
        if alt:
            return Reflection(
                task_id=task.id, success=False, action=ReflectionAction.ALTERNATIVE,
                reason="Exhausted retries; trying an alternative command.",
                alternative_command=alt, unexpected=True,
            )
        return Reflection(
            task_id=task.id, success=False, action=ReflectionAction.ABORT,
            reason="Exhausted retries with no viable alternative.", unexpected=True,
        )

    # ── Helpers ──

    @staticmethod
    def _is_empty(value: Any) -> bool:
        if value is None:
            return True
        if isinstance(value, (list, tuple, set, dict, str)):
            return len(value) == 0
        return False

    @staticmethod
    def _fallback(command: str) -> str:
        parts = command.split()
        if not parts:
            return ""
        name = parts[0]
        target = parts[1] if len(parts) > 1 else ""
        template = _FALLBACKS.get(name)
        if not template:
            return ""
        return template.format(target=target).strip()

    def _emit(self, reflection: Reflection) -> None:
        if self._bus is None:
            return
        try:
            self._bus.emit("agent.reflection", reflection.to_dict())
        except Exception:
            pass
