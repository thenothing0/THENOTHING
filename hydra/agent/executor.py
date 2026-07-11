"""Executor — runs tasks ONLY through an injected ``execute_command`` callable.

The agent never bypasses HYDRA: the caller injects
``HydraFacade.execute_command`` (or a thin adapter over it). The executor never
imports or calls services directly. It adds retry, timeout, cancellation and
recovery around that single callable, updating task state and emitting events.
"""

from __future__ import annotations

import concurrent.futures
import threading
from typing import Any, Callable

from hydra.agent.models import Task, TaskState

ExecuteFn = Callable[[str], Any]


class Executor:
    """Sequential + bounded-parallel task execution via one command callable."""

    def __init__(
        self,
        execute_command: ExecuteFn,
        event_bus=None,
        max_retries: int = 1,
        timeout: float | None = None,
        max_workers: int = 4,
    ):
        self._execute = execute_command
        self._bus = event_bus
        self.max_retries = max(0, max_retries)
        self.timeout = timeout
        self._max_workers = max(1, max_workers)
        self._cancel = threading.Event()
        self._pool: concurrent.futures.ThreadPoolExecutor | None = None

    # ── Cancellation ──

    def cancel(self) -> None:
        self._cancel.set()

    def reset(self) -> None:
        self._cancel.clear()

    @property
    def cancelled(self) -> bool:
        return self._cancel.is_set()

    # ── Single task ──

    def execute_task(self, task: Task) -> Any:
        """Run one task with retry/timeout/cancel; update its state; return result."""
        if self._cancel.is_set():
            self._mark(task, TaskState.CANCELLED)
            return None

        # Attempts PER CALL are bounded by max_retries. The cross-iteration retry
        # budget (task.max_attempts) is owned by reflection-driven replanning, so
        # a single execute_task call always makes at least one attempt.
        last_value: Any = None
        for _ in range(1 + self.max_retries):
            if self._cancel.is_set():
                self._mark(task, TaskState.CANCELLED)
                return last_value
            task.attempts += 1
            task.state = TaskState.RUNNING
            self._emit("agent.task.started", task)
            ok, value = self._attempt(task.command)
            last_value = value
            if ok and not self._is_failure(value):
                task.result = self._result_value(value)
                task.error = ""
                self._mark(task, TaskState.COMPLETED)
                return value
            task.error = self._error_text(value)
        self._mark(task, TaskState.FAILED)
        return last_value

    # ── Parallel batch (only parallel-safe tasks) ──

    def execute_parallel(self, tasks: list[Task]) -> list[Any]:
        """Run parallel-safe tasks concurrently; others fall back to sequential."""
        safe = [t for t in tasks if t.parallel_safe]
        unsafe = [t for t in tasks if not t.parallel_safe]
        results: list[Any] = [self.execute_task(t) for t in unsafe]
        if not safe:
            return results
        pool = self._ensure_pool()
        futures = {pool.submit(self.execute_task, t): t for t in safe}
        for fut in concurrent.futures.as_completed(futures):
            try:
                results.append(fut.result())
            except Exception:
                results.append(None)
        return results

    # ── Internals ──

    def _attempt(self, command: str) -> tuple[bool, Any]:
        """Run one command invocation with an optional timeout. (ok, value)."""
        try:
            if self.timeout:
                pool = self._ensure_pool()
                future = pool.submit(self._execute, command)
                try:
                    return True, future.result(timeout=self.timeout)
                except concurrent.futures.TimeoutError:
                    future.cancel()
                    return False, {"error": f"timeout after {self.timeout}s"}
            return True, self._execute(command)
        except Exception as exc:  # recovery: never let a bad command crash the loop
            return False, {"error": str(exc)}

    def _ensure_pool(self) -> concurrent.futures.ThreadPoolExecutor:
        if self._pool is None:
            self._pool = concurrent.futures.ThreadPoolExecutor(
                max_workers=self._max_workers, thread_name_prefix="agent-exec")
        return self._pool

    def shutdown(self) -> None:
        if self._pool is not None:
            self._pool.shutdown(wait=False, cancel_futures=True)
            self._pool = None

    @staticmethod
    def _is_failure(value: Any) -> bool:
        status = getattr(value, "status", None)
        if status == "error":
            return True
        if isinstance(value, dict) and value.get("error"):
            return True
        return False

    @staticmethod
    def _error_text(value: Any) -> str:
        errors = getattr(value, "errors", None)
        if errors:
            return "; ".join(str(e) for e in errors)
        if isinstance(value, dict) and value.get("error"):
            return str(value["error"])
        return "task failed"

    @staticmethod
    def _result_value(value: Any) -> Any:
        output = getattr(value, "output", None)
        if output is not None:
            return output
        status = getattr(value, "status", None)
        if status is not None:
            return {"status": status}
        return value

    def _mark(self, task: Task, state: TaskState) -> None:
        task.state = state
        self._emit(f"agent.task.{state.value}", task)

    def _emit(self, event_type: str, task: Task) -> None:
        if self._bus is None:
            return
        try:
            self._bus.emit(event_type, {
                "task_id": task.id,
                "command": task.command,
                "description": task.description,
                "attempts": task.attempts,
                "state": task.state.value,
                "error": task.error,
            })
        except Exception:
            pass
