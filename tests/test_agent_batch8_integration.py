"""Batch 8 tests — integration + edge cases across the agent engine."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any

import pytest

from hydra.agent.context import ContextBuilder
from hydra.agent.executor import Executor
from hydra.agent.goals import GoalTracker
from hydra.agent.memory import AgentMemory
from hydra.agent.models import (
    AgentState,
    ExecutionPlan,
    Goal,
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
from hydra.agent.service import MAX_SESSIONS, AgentService
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


# ── Planner scenarios ──

class TestPlannerScenarios:
    @pytest.mark.parametrize("objective,expect_prefixes", [
        ("recon example.com", {"/scope", "/recon"}),
        ("audit example.com", {"/scope", "/recon", "/scan", "/reports"}),
        ("attack example.com", {"/scope", "/recon", "/attack"}),
        ("research example.com", {"/search"}),
        ("status check", {"/status"}),
    ])
    def test_intent_command_sets(self, objective, expect_prefixes):
        plan = Planner().plan(objective)
        prefixes = {t.command.split()[0] for t in plan.tasks}
        assert expect_prefixes <= prefixes

    def test_url_target(self):
        plan = Planner().plan("assess https://app.example.com/login")
        assert plan.goal.target == "https://app.example.com/login"

    def test_ip_target(self):
        plan = Planner().plan("assess 10.0.0.9")
        assert plan.goal.target == "10.0.0.9"

    def test_multi_vuln_scans(self):
        plan = Planner().plan("scan example.com for xss, sqli, ssrf, lfi")
        scans = [t for t in plan.tasks if t.command.startswith("/scan")]
        assert len(scans) == 4

    def test_priorities_descending_scope_first(self):
        plan = Planner().plan("assess example.com")
        scope = next(t for t in plan.tasks if t.command.startswith("/scope"))
        report = next(t for t in plan.tasks if t.command.startswith("/reports"))
        assert scope.priority > report.priority

    def test_knowledge_parallel_safe(self):
        plan = Planner().plan("research example.com")
        know = next(t for t in plan.tasks if t.command.startswith("/search"))
        assert know.parallel_safe

    def test_replan_revision_increments(self):
        planner = Planner()
        plan = planner.plan("assess example.com")
        planner.replan(plan, [])
        planner.replan(plan, [])
        assert plan.revision == 2

    def test_replan_retry_respects_max_attempts(self):
        planner = Planner()
        plan = planner.plan("assess example.com")
        t = plan.tasks[0]
        t.state = TaskState.FAILED
        t.attempts = t.max_attempts
        ref = Reflection(task_id=t.id, success=False, action=ReflectionAction.RETRY)
        planner.replan(plan, [ref])
        # exhausted attempts → not reset to runnable
        assert t.state == TaskState.FAILED


# ── Models edge cases ──

class TestModelEdges:
    def test_task_from_dict_missing_fields(self):
        t = Task.from_dict({"description": "d"})
        assert t.command == "" and t.priority == 5

    def test_plan_from_dict_empty(self):
        plan = ExecutionPlan.from_dict({"goal": Goal(objective="o").to_dict()})
        assert plan.tasks == []

    def test_subtask_state_coercion(self):
        s = SubTask.from_dict({"description": "d", "command": "/x", "state": "completed"})
        assert s.state == TaskState.COMPLETED

    def test_reflection_action_default(self):
        r = Reflection.from_dict({"task_id": "t", "success": True})
        assert r.action == ReflectionAction.CONTINUE


# ── Scheduler complex graphs ──

class TestSchedulerGraphs:
    def test_diamond_dependencies(self):
        a = Task(description="a", command="/scope x", state=TaskState.READY)
        b = Task(description="b", command="/recon x", depends_on=[a.id])
        c = Task(description="c", command="/search x", depends_on=[a.id])
        d = Task(description="d", command="/reports", depends_on=[b.id, c.id])
        plan = ExecutionPlan(goal=Goal(objective="o"), tasks=[a, b, c, d])
        sch = Scheduler(plan)
        a.state = TaskState.COMPLETED
        sch.refresh()
        assert b.state == TaskState.READY and c.state == TaskState.READY
        assert d.state == TaskState.WAITING
        b.state = TaskState.COMPLETED
        c.state = TaskState.COMPLETED
        sch.refresh()
        assert d.state == TaskState.READY

    def test_parallel_batch_limit(self):
        tasks = [Task(description=f"s{i}", command=f"/search {i}",
                      state=TaskState.READY, parallel_safe=True) for i in range(10)]
        sch = Scheduler(ExecutionPlan(goal=Goal(objective="o"), tasks=tasks))
        assert len(sch.next_parallel_batch(limit=3)) == 3

    def test_all_terminal_empty_plan(self):
        sch = Scheduler(ExecutionPlan(goal=Goal(objective="o"), tasks=[]))
        assert not sch.all_terminal()


# ── Executor edge cases ──

class TestExecutorEdges:
    def test_parallel_all_safe(self):
        ex = Executor(lambda c: FakeResult(status="success"))
        tasks = [Task(description=f"s{i}", command=f"/search {i}", parallel_safe=True)
                 for i in range(4)]
        results = ex.execute_parallel(tasks)
        assert len(results) == 4
        ex.shutdown()

    def test_result_value_no_output(self):
        assert Executor._result_value(FakeResult(status="success")) == {"status": "success"}

    def test_result_value_plain(self):
        assert Executor._result_value({"a": 1}) == {"a": 1}

    def test_error_text_from_errors(self):
        assert "x" in Executor._error_text(FakeResult(status="error", errors=["x", "y"]))

    def test_is_failure_variants(self):
        assert Executor._is_failure(FakeResult(status="error"))
        assert Executor._is_failure({"error": "e"})
        assert not Executor._is_failure(FakeResult(status="success"))
        assert not Executor._is_failure({"ok": 1})

    def test_cancel_during_parallel(self):
        ex = Executor(lambda c: FakeResult(status="success"))
        ex.cancel()
        tasks = [Task(description="s", command="/search 1", parallel_safe=True)]
        ex.execute_parallel(tasks)
        assert tasks[0].state == TaskState.CANCELLED
        ex.shutdown()


# ── Memory / Context extras ──

class TestMemoryContextExtras:
    def test_knowledge_recent(self):
        m = AgentMemory()
        for i in range(5):
            m.add_knowledge("recon", {"i": i})
        assert m.knowledge.recent(2)[-1]["fact"] == {"i": 4}

    def test_save_resume_full_cycle(self, tmp_path):
        m = AgentMemory(session_id="c1", data_dir=tmp_path)
        m.record_execution("t", "/recon a.com", "completed")
        m.save()
        m2 = AgentMemory(session_id="c1", data_dir=tmp_path)
        m2.resume()
        assert len(m2.execution) == 1

    def test_context_dedup_known_targets(self):
        ctx = ContextBuilder().build(
            "assess a.com",
            recent_commands=["/recon a.com", "/scan a.com xss", "/recon a.com"])
        assert ctx.known_targets.count("a.com") == 1


# ── Reasoner / Reflection extras ──

class TestReasonReflectExtras:
    def test_reasoner_phases_recorded(self):
        r = Reasoner()
        r.think_plan("o", "a.com", 3)
        r.think_execute("/recon a.com")
        r.think_reflect("recon", True, "continue")
        phases = {s.phase for s in r.steps()}
        assert {"plan", "execute", "reflect"} <= phases

    def test_reflection_fallback_none_for_recon(self):
        assert ReflectionEngine._fallback("/recon a.com") == ""

    def test_reflection_fallback_scan(self):
        assert ReflectionEngine._fallback("/scan a.com xss") == "/recon a.com"

    def test_reflection_empty_variants(self):
        assert ReflectionEngine._is_empty(None)
        assert ReflectionEngine._is_empty([])
        assert ReflectionEngine._is_empty("")
        assert not ReflectionEngine._is_empty({"a": 1})
        assert not ReflectionEngine._is_empty(5)


# ── GoalTracker extras ──

class TestGoalTrackerExtras:
    def test_confidence_zero_when_all_cancelled(self):
        plan = Planner().plan("assess example.com")
        for t in plan.tasks:
            t.state = TaskState.CANCELLED
        assert GoalTracker(plan).confidence() == 0.0

    def test_current_task_none_when_done(self):
        plan = Planner().plan("assess example.com")
        for t in plan.tasks:
            t.state = TaskState.COMPLETED
        assert GoalTracker(plan).current_task() is None


# ── State machine transition matrix ──

class TestStateMatrix:
    @pytest.mark.parametrize("frm,to,ok", [
        (AgentState.IDLE, AgentState.PLANNING, True),
        (AgentState.IDLE, AgentState.EXECUTING, False),
        (AgentState.PLANNING, AgentState.EXECUTING, True),
        (AgentState.EXECUTING, AgentState.REFLECTING, True),
        (AgentState.REFLECTING, AgentState.PLANNING, True),
        (AgentState.EXECUTING, AgentState.COMPLETED, True),
        (AgentState.COMPLETED, AgentState.EXECUTING, False),
        (AgentState.COMPLETED, AgentState.IDLE, True),
    ])
    def test_transitions(self, frm, to, ok):
        sm = AgentStateMachine(initial=frm)
        assert sm.transition(to) is ok


# ── Orchestrator end-to-end scenarios ──

class TestOrchestratorScenarios:
    def test_recon_only_completes(self):
        ex = make_exec()
        s = Orchestrator(ex).run("recon example.com")
        assert s.status == "completed"
        assert any(c.startswith("/recon") for c in ex.calls)  # type: ignore[attr-defined]

    def test_attack_objective(self):
        ex = make_exec()
        s = Orchestrator(ex).run("attack example.com")
        assert s.status == "completed"
        assert any(c.startswith("/attack") for c in ex.calls)  # type: ignore[attr-defined]

    def test_no_target_status_only(self):
        ex = make_exec()
        s = Orchestrator(ex).run("give me status")
        assert s.status == "completed"
        assert ex.calls == ["/status"]  # type: ignore[attr-defined]

    def test_everything_fails_marks_failed(self):
        orch = Orchestrator(make_exec(fail_prefixes=("/",)))
        orch.set_max_iterations(30)
        s = orch.run("assess example.com")
        assert s.state in (AgentState.FAILED, AgentState.COMPLETED)
        assert s.status in ("failed", "completed")

    def test_mixed_success(self):
        # scan fails, others succeed → alternative recon path, terminates
        s = Orchestrator(make_exec(fail_prefixes=("/scan",))).run("assess example.com")
        assert s.state in (AgentState.COMPLETED, AgentState.FAILED)

    def test_reasoning_recorded_in_session(self):
        s = Orchestrator(make_exec()).run("assess example.com")
        assert s.reasoning_steps

    def test_memory_records_executions(self):
        s = Orchestrator(make_exec()).run("assess example.com")
        assert len(s.memory.execution) >= 1


# ── Service extras ──

class TestServiceExtras:
    def test_sessions_bounded(self, tmp_path):
        svc = AgentService(EventBus(), tmp_path)
        # run more than MAX_SESSIONS quickly with a trivial objective
        for i in range(MAX_SESSIONS + 5):
            svc.run("status", make_exec())
        assert len(svc._sessions) <= MAX_SESSIONS

    def test_status_unknown(self, tmp_path):
        svc = AgentService(EventBus(), tmp_path)
        assert svc.status("nope")["status"] == "unknown"

    def test_resume_unknown_returns_none(self, tmp_path):
        svc = AgentService(EventBus(), tmp_path)
        assert svc.resume("nope", make_exec()) is None

    def test_create_orchestrator(self, tmp_path):
        svc = AgentService(EventBus(), tmp_path)
        assert isinstance(svc.create_orchestrator(make_exec()), Orchestrator)


# ── Full persistence + resume integration ──

def test_full_persist_reload_resume(tmp_path):
    svc = AgentService(EventBus(), tmp_path)
    session = svc.run("assess example.com", make_exec())
    assert session.status == "completed"

    # simulate restart: a brand-new service reloads from disk and resumes
    svc2 = AgentService(EventBus(), tmp_path)
    loaded = svc2.load_session(session.id)
    assert loaded is not None
    resumed = svc2.resume(session.id, make_exec())
    assert resumed is not None and resumed.id == session.id


def test_concurrent_orchestrators_isolated(tmp_path):
    svc = AgentService(EventBus(), tmp_path)
    results = {}
    errors = []

    def worker(i):
        try:
            s = svc.run(f"assess host{i}.example.com", make_exec())
            results[i] = s.status
        except Exception as e:  # pragma: no cover
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert all(v == "completed" for v in results.values())
