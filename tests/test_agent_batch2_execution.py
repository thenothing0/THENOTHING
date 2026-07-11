"""Batch 2 tests — scheduler and executor."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any

from hydra.agent.executor import Executor
from hydra.agent.models import ExecutionPlan, Goal, Task, TaskState
from hydra.agent.scheduler import Scheduler
from hydra.services.event_bus import EventBus


@dataclass
class FakeResult:
    """Duck-typed CommandResult for executor tests."""

    status: str = "success"
    output: Any = None
    errors: list = field(default_factory=list)


def _plan(tasks):
    return ExecutionPlan(goal=Goal(objective="o", target="a.com"), tasks=tasks)


def _linear_plan():
    a = Task(description="a", command="/scope a.com", state=TaskState.READY)
    b = Task(description="b", command="/recon a.com", depends_on=[a.id])
    c = Task(description="c", command="/scan a.com xss", depends_on=[b.id])
    return _plan([a, b, c]), a, b, c


# ── Scheduler ──

class TestScheduler:
    def test_initial_ready_is_dep_free(self):
        plan, a, b, c = _linear_plan()
        sch = Scheduler(plan)
        ready = sch.ready_tasks()
        assert [t.id for t in ready] == [a.id]

    def test_refresh_promotes_on_completion(self):
        plan, a, b, c = _linear_plan()
        sch = Scheduler(plan)
        a.state = TaskState.COMPLETED
        sch.refresh()
        assert b.state == TaskState.READY
        assert c.state == TaskState.WAITING

    def test_next_task_priority(self):
        t1 = Task(description="lo", command="/status", state=TaskState.READY, priority=2)
        t2 = Task(description="hi", command="/status", state=TaskState.READY, priority=9)
        sch = Scheduler(_plan([t1, t2]))
        assert sch.next_task().id == t2.id

    def test_mark_completed_refreshes(self):
        plan, a, b, c = _linear_plan()
        sch = Scheduler(plan)
        sch.mark(a, TaskState.COMPLETED)
        assert b.state == TaskState.READY

    def test_all_terminal(self):
        plan, a, b, c = _linear_plan()
        sch = Scheduler(plan)
        assert not sch.all_terminal()
        for t in (a, b, c):
            t.state = TaskState.COMPLETED
        assert sch.all_terminal()

    def test_is_stuck_when_dep_failed(self):
        plan, a, b, c = _linear_plan()
        sch = Scheduler(plan)
        a.state = TaskState.FAILED
        assert sch.is_stuck()

    def test_not_stuck_with_ready(self):
        plan, a, b, c = _linear_plan()
        sch = Scheduler(plan)
        assert not sch.is_stuck()

    def test_has_runnable(self):
        plan, a, b, c = _linear_plan()
        sch = Scheduler(plan)
        assert sch.has_runnable()
        for t in (a, b, c):
            t.state = TaskState.COMPLETED
        assert not sch.has_runnable()

    def test_cancel_pending(self):
        plan, a, b, c = _linear_plan()
        sch = Scheduler(plan)
        a.state = TaskState.COMPLETED
        sch.cancel_pending()
        assert b.state == TaskState.CANCELLED and c.state == TaskState.CANCELLED
        assert a.state == TaskState.COMPLETED

    def test_parallel_batch_only_safe(self):
        s1 = Task(description="s", command="/search x", state=TaskState.READY, parallel_safe=True)
        s2 = Task(description="u", command="/recon x", state=TaskState.READY, parallel_safe=False)
        sch = Scheduler(_plan([s1, s2]))
        batch = sch.next_parallel_batch()
        assert [t.id for t in batch] == [s1.id]

    def test_emits_events(self):
        plan, a, b, c = _linear_plan()
        bus = EventBus()
        seen = []
        bus.subscribe("agent.task.*", lambda e: seen.append(e.type))
        sch = Scheduler(plan, event_bus=bus)
        sch.mark(a, TaskState.COMPLETED)
        assert "agent.task.completed" in seen


# ── Executor ──

class TestExecutor:
    def test_success(self):
        calls = []
        ex = Executor(lambda cmd: calls.append(cmd) or FakeResult(status="success", output={"ok": 1}))
        t = Task(description="d", command="/status")
        ex.execute_task(t)
        assert t.state == TaskState.COMPLETED
        assert t.result == {"ok": 1}
        assert calls == ["/status"]

    def test_failure_marks_failed(self):
        ex = Executor(lambda cmd: FakeResult(status="error", errors=["bad"]), max_retries=0)
        t = Task(description="d", command="/x")
        ex.execute_task(t)
        assert t.state == TaskState.FAILED
        assert "bad" in t.error

    def test_retry_increments_attempts(self):
        n = {"c": 0}

        def fn(cmd):
            n["c"] += 1
            return FakeResult(status="error", errors=["e"])

        t = Task(description="d", command="/x", max_attempts=5)
        Executor(fn, max_retries=1).execute_task(t)
        assert t.attempts == 2  # 1 + max_retries
        assert n["c"] == 2

    def test_retry_succeeds_second_time(self):
        n = {"c": 0}

        def fn(cmd):
            n["c"] += 1
            return FakeResult(status="error") if n["c"] == 1 else FakeResult(status="success", output="ok")

        t = Task(description="d", command="/x", max_attempts=5)
        Executor(fn, max_retries=2).execute_task(t)
        assert t.state == TaskState.COMPLETED and t.result == "ok"

    def test_dict_error_result(self):
        ex = Executor(lambda cmd: {"error": "boom"}, max_retries=0)
        t = Task(description="d", command="/x")
        ex.execute_task(t)
        assert t.state == TaskState.FAILED and "boom" in t.error

    def test_exception_recovered(self):
        def fn(cmd):
            raise RuntimeError("explode")

        ex = Executor(fn, max_retries=0)
        t = Task(description="d", command="/x")
        ex.execute_task(t)  # must not raise
        assert t.state == TaskState.FAILED and "explode" in t.error

    def test_timeout(self):
        def slow(cmd):
            time.sleep(0.3)
            return FakeResult(status="success")

        ex = Executor(slow, timeout=0.05, max_retries=0)
        t = Task(description="d", command="/x")
        ex.execute_task(t)
        assert t.state == TaskState.FAILED and "timeout" in t.error
        ex.shutdown()

    def test_cancel_before_run(self):
        ran = []
        ex = Executor(lambda cmd: ran.append(cmd))
        ex.cancel()
        t = Task(description="d", command="/x")
        ex.execute_task(t)
        assert t.state == TaskState.CANCELLED and not ran

    def test_reset_clears_cancel(self):
        ex = Executor(lambda cmd: FakeResult())
        ex.cancel()
        assert ex.cancelled
        ex.reset()
        assert not ex.cancelled

    def test_events_emitted(self):
        bus = EventBus()
        seen = []
        bus.subscribe("agent.task.*", lambda e: seen.append(e.type))
        ex = Executor(lambda cmd: FakeResult(status="success"), event_bus=bus)
        ex.execute_task(Task(description="d", command="/status"))
        assert "agent.task.started" in seen
        assert "agent.task.completed" in seen

    def test_execute_parallel(self):
        lock = threading.Lock()
        seen = []

        def fn(cmd):
            with lock:
                seen.append(cmd)
            return FakeResult(status="success")

        ex = Executor(fn)
        tasks = [
            Task(description="s1", command="/search a", parallel_safe=True),
            Task(description="s2", command="/search b", parallel_safe=True),
            Task(description="u", command="/recon c", parallel_safe=False),
        ]
        results = ex.execute_parallel(tasks)
        assert len(results) == 3
        assert set(seen) == {"/search a", "/search b", "/recon c"}
        for t in tasks:
            assert t.state == TaskState.COMPLETED
        ex.shutdown()

    def test_commandresult_success_output(self):
        ex = Executor(lambda cmd: FakeResult(status="success", output={"type": "status"}))
        t = Task(description="d", command="/status")
        ex.execute_task(t)
        assert t.result == {"type": "status"}
