"""Batch 8b — additional coverage to exceed the 250-test bar and harden edges."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from hydra.agent import prompts
from hydra.agent.executor import Executor
from hydra.agent.goals import GoalTracker
from hydra.agent.memory import AgentMemory
from hydra.agent.models import (
    AgentState,
    Goal,
    Observation,
    ReasoningStep,
    Task,
    TaskState,
)
from hydra.agent.orchestrator import Orchestrator
from hydra.agent.planner import Planner
from hydra.agent.reasoner import Reasoner
from hydra.agent.reflection import ReflectionEngine
from hydra.agent.scheduler import Scheduler
from hydra.agent.service import AgentService
from hydra.agent.state import AgentStateMachine
from hydra.services.event_bus import EventBus


@dataclass
class FakeResult:
    status: str = "success"
    output: Any = None
    errors: list = field(default_factory=list)


def make_exec(fail_prefixes=()):
    calls = []

    def ex(cmd):
        calls.append(cmd)
        if any(cmd.startswith(p) for p in fail_prefixes):
            return FakeResult(status="error", errors=["nope"])
        return FakeResult(status="success", output={"cmd": cmd})

    ex.calls = calls  # type: ignore[attr-defined]
    return ex


# ── prompts ──

class TestPromptsCoverage:
    @pytest.mark.parametrize("text,tgt", [
        ("assess api.example.com", "api.example.com"),
        ("hit sub.deep.example.co.uk", "sub.deep.example.co.uk"),
        ("example.com, please", "example.com"),
        ("no target here", ""),
    ])
    def test_extract_target(self, text, tgt):
        assert prompts.extract_target(text) == tgt

    def test_detect_steps_case_insensitive(self):
        assert prompts.detect_steps("RECON example.com")[0] == "scope"

    def test_default_steps_meta_present(self):
        for step in prompts.DEFAULT_STEPS:
            assert step in prompts.STEP_META

    def test_vuln_keyword_aliases(self):
        got = prompts.extract_vuln_classes("template injection and local file")
        assert "ssti" in got and "lfi" in got


# ── models ──

class TestModelsCoverage:
    def test_goal_from_dict_missing(self):
        assert Goal.from_dict({}).objective == ""

    def test_observation_missing(self):
        assert Observation.from_dict({}).source == ""

    def test_reasoning_step_missing(self):
        assert ReasoningStep.from_dict({}).phase == ""

    def test_task_empty_subtasks_roundtrip(self):
        t = Task(description="d", command="/status")
        assert Task.from_dict(t.to_dict()).subtasks == []

    def test_terminal_task_states(self):
        from hydra.agent.models import TERMINAL_TASK_STATES
        assert TaskState.COMPLETED in TERMINAL_TASK_STATES
        assert TaskState.READY not in TERMINAL_TASK_STATES


# ── scheduler ──

class TestSchedulerCoverage:
    def test_mark_cancelled_emits(self):
        bus = EventBus()
        seen = []
        bus.subscribe("agent.task.cancelled", lambda e: seen.append(e))
        t = Task(description="d", command="/x", state=TaskState.READY)
        sch = Scheduler(_plan([t]), event_bus=bus)
        sch.mark(t, TaskState.CANCELLED)
        assert seen

    def test_has_runnable_with_waiting(self):
        a = Task(description="a", command="/scope x", state=TaskState.READY)
        b = Task(description="b", command="/recon x", depends_on=[a.id])
        sch = Scheduler(_plan([a, b]))
        assert sch.has_runnable()

    def test_next_task_none_when_empty(self):
        assert Scheduler(_plan([])).next_task() is None


def _plan(tasks):
    return __import__("hydra.agent.models", fromlist=["ExecutionPlan"]).ExecutionPlan(
        goal=Goal(objective="o"), tasks=tasks)


# ── executor ──

class TestExecutorCoverage:
    def test_max_retries_two_attempts(self):
        n = {"c": 0}

        def fn(cmd):
            n["c"] += 1
            return FakeResult(status="error")

        t = Task(description="d", command="/x")
        Executor(fn, max_retries=2).execute_task(t)
        assert n["c"] == 3  # 1 + 2 retries

    def test_failure_emits_failed_event(self):
        bus = EventBus()
        seen = []
        bus.subscribe("agent.task.failed", lambda e: seen.append(e))
        Executor(lambda c: FakeResult(status="error"), event_bus=bus, max_retries=0).execute_task(
            Task(description="d", command="/x"))
        assert seen

    def test_shutdown_idempotent(self):
        ex = Executor(lambda c: FakeResult())
        ex.shutdown()
        ex.shutdown()  # no error


# ── reasoner ──

class TestReasonerCoverage:
    def test_observe_returns_data(self):
        obs = Reasoner().observe("scan", {"a": 1})
        assert obs.data == {"a": 1}

    def test_summarize_set(self):
        assert "item" in Reasoner.summarize({1, 2})

    def test_empty_dict_summary(self):
        assert Reasoner.summarize({}) == "empty dict"

    def test_recent_bounded(self):
        r = Reasoner()
        for i in range(10):
            r.note("x", str(i))
        assert len(r.recent(3)) == 3


# ── reflection ──

class TestReflectionCoverage:
    def test_success_empty_dict_missing(self):
        t = Task(description="d", command="/search x", state=TaskState.COMPLETED, result={})
        assert ReflectionEngine().reflect(t).missing_info

    def test_fallback_empty_command(self):
        assert ReflectionEngine._fallback("") == ""

    def test_reflect_non_terminal_treated_failure(self):
        t = Task(description="d", command="/recon a.com", state=TaskState.RUNNING,
                 attempts=3, max_attempts=3)
        ref = ReflectionEngine().reflect(t)
        assert not ref.success


# ── goals ──

class TestGoalsCoverage:
    def test_estimated_remaining(self):
        plan = Planner().plan("assess example.com")
        gt = GoalTracker(plan)
        assert gt.estimated_remaining() == len(plan.tasks)

    def test_snapshot_revision(self):
        plan = Planner().plan("assess example.com")
        plan.revision = 4
        assert GoalTracker(plan).snapshot()["revision"] == 4

    def test_running_partition(self):
        plan = Planner().plan("assess example.com")
        plan.tasks[0].state = TaskState.RUNNING
        assert len(GoalTracker(plan).running()) == 1


# ── state ──

class TestStateCoverage:
    def test_force_notifies(self):
        sm = AgentStateMachine()
        seen = []
        sm.on_change(lambda a, b: seen.append((a, b)))
        sm.force(AgentState.EXECUTING)
        assert seen == [(AgentState.IDLE, AgentState.EXECUTING)]

    def test_reset_from_non_terminal(self):
        sm = AgentStateMachine(initial=AgentState.EXECUTING)
        sm.reset()
        assert sm.state == AgentState.IDLE

    def test_is_terminal_false_initial(self):
        assert not AgentStateMachine().is_terminal()


# ── orchestrator / service ──

class TestOrchestratorServiceCoverage:
    def test_set_max_iterations_min_one(self):
        orch = Orchestrator(make_exec())
        orch.set_max_iterations(0)
        assert orch._maxit == 1

    def test_status_after_run(self):
        orch = Orchestrator(make_exec())
        orch.run("assess example.com")
        st = orch.status()
        assert "completion_pct" in st and st["status"] == "completed"

    def test_resume_completed_session_noop(self, tmp_path):
        svc = AgentService(EventBus(), tmp_path)
        session = svc.run("status", make_exec())
        again = svc.resume(session.id, make_exec())
        assert again is not None and again.status == "completed"

    def test_list_sessions_summary_fields(self, tmp_path):
        svc = AgentService(EventBus(), tmp_path)
        svc.run("assess example.com", make_exec())
        summ = svc.list_sessions()[0]
        assert "objective" in summ and "tasks" in summ and "state" in summ

    def test_save_session_returns_true(self, tmp_path):
        svc = AgentService(EventBus(), tmp_path)
        session = svc.run("status", make_exec())
        assert svc.save_session(session) is True

    def test_memory_persisted_after_run(self, tmp_path):
        svc = AgentService(EventBus(), tmp_path)
        session = svc.run("assess example.com", make_exec())
        mem = AgentMemory(session_id=session.id, data_dir=tmp_path)
        assert mem.resume()
        assert len(mem.execution) >= 1
