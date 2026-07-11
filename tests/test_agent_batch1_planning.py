"""Batch 1 tests — models, prompts, planner, goals, state machine."""

from __future__ import annotations

import threading

import pytest

from hydra.agent import prompts
from hydra.agent.goals import GoalTracker
from hydra.agent.models import (
    AgentState,
    ExecutionPlan,
    Goal,
    Observation,
    ReasoningStep,
    Reflection,
    ReflectionAction,
    SubTask,
    Task,
    TaskState,
)
from hydra.agent.planner import Planner
from hydra.agent.state import AgentStateMachine


# ── models ──

class TestModels:
    def test_task_state_values(self):
        assert {s.value for s in TaskState} == {
            "ready", "waiting", "running", "failed", "completed", "cancelled"}

    def test_agent_state_values(self):
        assert {s.value for s in AgentState} == {
            "idle", "planning", "executing", "waiting", "reflecting",
            "completed", "failed", "cancelled"}

    def test_reflection_action_values(self):
        assert {a.value for a in ReflectionAction} == {
            "retry", "alternative", "continue", "abort"}

    def test_subtask_roundtrip(self):
        s = SubTask(description="d", command="/status")
        r = SubTask.from_dict(s.to_dict())
        assert r.id == s.id and r.command == "/status" and r.state == TaskState.READY

    def test_task_defaults(self):
        t = Task(description="x")
        assert t.priority == 5 and t.confidence == 0.5
        assert t.state == TaskState.WAITING and t.max_attempts == 3
        assert not t.is_terminal

    def test_task_is_terminal(self):
        for st in (TaskState.COMPLETED, TaskState.FAILED, TaskState.CANCELLED):
            assert Task(description="x", state=st).is_terminal
        for st in (TaskState.READY, TaskState.WAITING, TaskState.RUNNING):
            assert not Task(description="x", state=st).is_terminal

    def test_task_roundtrip(self):
        t = Task(description="d", command="/recon a.com", depends_on=["p1"],
                 priority=8, confidence=0.7, subtasks=[SubTask("s", "/status")])
        r = Task.from_dict(t.to_dict())
        assert r.id == t.id and r.command == t.command
        assert r.depends_on == ["p1"] and r.priority == 8
        assert len(r.subtasks) == 1 and r.subtasks[0].command == "/status"

    def test_goal_roundtrip(self):
        g = Goal(objective="assess a.com", target="a.com")
        r = Goal.from_dict(g.to_dict())
        assert r.id == g.id and r.target == "a.com"

    def test_plan_roundtrip_and_lookup(self):
        g = Goal(objective="o")
        t = Task(description="d", command="/status")
        plan = ExecutionPlan(goal=g, tasks=[t], stop_conditions=["x"])
        r = ExecutionPlan.from_dict(plan.to_dict())
        assert r.id == plan.id and len(r.tasks) == 1
        assert r.task_by_id(t.id) is not None
        assert r.task_by_id("nope") is None

    def test_observation_roundtrip(self):
        o = Observation(source="recon", data={"k": 1})
        r = Observation.from_dict(o.to_dict())
        assert r.source == "recon" and r.data == {"k": 1}

    def test_reasoning_step_roundtrip(self):
        s = ReasoningStep(phase="think", thought="hmm")
        r = ReasoningStep.from_dict(s.to_dict())
        assert r.phase == "think" and r.thought == "hmm"

    def test_reflection_roundtrip(self):
        ref = Reflection(task_id="t1", success=False,
                         action=ReflectionAction.RETRY, missing_info=True)
        r = Reflection.from_dict(ref.to_dict())
        assert r.task_id == "t1" and r.action == ReflectionAction.RETRY
        assert r.missing_info is True

    def test_unique_ids(self):
        assert len({Task(description="x").id for _ in range(50)}) == 50


# ── prompts ──

class TestPrompts:
    @pytest.mark.parametrize("text,expected", [
        ("assess example.com now", "example.com"),
        ("scan https://app.example.com/login", "https://app.example.com/login"),
        ("probe 10.0.0.5 please", "10.0.0.5"),
        ("just do a status check", ""),
    ])
    def test_extract_target(self, text, expected):
        assert prompts.extract_target(text) == expected

    def test_extract_vuln_classes(self):
        got = prompts.extract_vuln_classes("look for xss and sql injection")
        assert "xss" in got and "sqli" in got

    def test_extract_vuln_classes_empty(self):
        assert prompts.extract_vuln_classes("just recon") == []

    @pytest.mark.parametrize("text,first_step", [
        ("full assessment of a.com", "scope"),
        ("recon a.com", "scope"),
        ("scan a.com", "recon"),
        ("research the topic", "knowledge"),
        ("something vague", "scope"),  # default steps
    ])
    def test_detect_steps(self, text, first_step):
        assert prompts.detect_steps(text)[0] == first_step

    def test_step_meta_covers_steps(self):
        for steps in prompts.INTENT_STEPS.values():
            for step in steps:
                assert step in prompts.STEP_META


# ── planner ──

class TestPlanner:
    def setup_method(self):
        self.planner = Planner()

    def test_plan_returns_plan(self):
        plan = self.planner.plan("assess example.com")
        assert isinstance(plan, ExecutionPlan)
        assert plan.goal.target == "example.com"
        assert plan.tasks

    def test_all_commands_are_slash(self):
        plan = self.planner.plan("full pentest of example.com for xss and sqli")
        for t in plan.tasks:
            assert t.command.startswith("/"), t.command

    def test_commands_use_real_names(self):
        plan = self.planner.plan("assess example.com")
        names = {t.command.split()[0] for t in plan.tasks}
        allowed = {"/scope", "/recon", "/scan", "/attack", "/search", "/reports", "/status"}
        assert names <= allowed

    def test_recon_depends_on_scope(self):
        plan = self.planner.plan("assess example.com")
        scope = next(t for t in plan.tasks if t.command.startswith("/scope"))
        recon = next(t for t in plan.tasks if t.command.startswith("/recon"))
        assert scope.id in recon.depends_on

    def test_scan_depends_on_recon(self):
        plan = self.planner.plan("assess example.com")
        recon = next(t for t in plan.tasks if t.command.startswith("/recon"))
        scan = next(t for t in plan.tasks if t.command.startswith("/scan"))
        assert recon.id in scan.depends_on

    def test_scan_per_vuln_class(self):
        plan = self.planner.plan("scan example.com for xss and sqli and ssrf")
        scans = [t for t in plan.tasks if t.command.startswith("/scan")]
        assert len(scans) == 3

    def test_default_scan_classes_when_unspecified(self):
        plan = self.planner.plan("scan example.com")
        scans = [t for t in plan.tasks if t.command.startswith("/scan")]
        classes = {t.command.split()[2] for t in scans}
        assert classes == {"xss", "sqli"}

    def test_no_target_degrades_to_status(self):
        plan = self.planner.plan("give me a status update")
        assert len(plan.tasks) == 1
        assert plan.tasks[0].command == "/status"

    def test_scope_skipped_without_target(self):
        plan = self.planner.plan("do recon")  # no target
        assert all(not t.command.startswith("/scope") for t in plan.tasks)

    def test_confidence_bounded(self):
        plan = self.planner.plan("full pentest of example.com")
        for t in plan.tasks:
            assert 0.0 <= t.confidence <= 1.0

    def test_stop_conditions_present(self):
        plan = self.planner.plan("assess example.com")
        assert plan.stop_conditions == list(prompts.STOP_CONDITIONS)

    def test_initial_ready_states(self):
        plan = self.planner.plan("assess example.com")
        ready = [t for t in plan.tasks if t.state == TaskState.READY]
        # Only dependency-free tasks start READY (e.g. scope, knowledge).
        assert ready
        for t in ready:
            assert not t.depends_on

    def test_replan_retry_resets_task(self):
        plan = self.planner.plan("assess example.com")
        t = plan.tasks[0]
        t.state = TaskState.FAILED
        t.attempts = 1
        ref = Reflection(task_id=t.id, success=False, action=ReflectionAction.RETRY)
        self.planner.replan(plan, [ref])
        assert t.state in (TaskState.READY, TaskState.WAITING)
        assert plan.revision == 1

    def test_replan_alternative_swaps_command(self):
        plan = self.planner.plan("assess example.com")
        t = plan.tasks[0]
        t.state = TaskState.FAILED
        ref = Reflection(task_id=t.id, success=False,
                         action=ReflectionAction.ALTERNATIVE,
                         alternative_command="/status")
        self.planner.replan(plan, [ref])
        assert t.command == "/status"

    def test_replan_abort_cancels_remaining(self):
        plan = self.planner.plan("assess example.com")
        t = plan.tasks[0]
        ref = Reflection(task_id=t.id, success=False, action=ReflectionAction.ABORT)
        self.planner.replan(plan, [ref])
        assert all(t.state == TaskState.CANCELLED for t in plan.tasks)

    def test_replan_unknown_task_id_noop(self):
        plan = self.planner.plan("assess example.com")
        ref = Reflection(task_id="nope", success=False, action=ReflectionAction.RETRY)
        self.planner.replan(plan, [ref])
        assert plan.revision == 1

    def test_context_boost_known_target(self):
        p = Planner()
        plan_lo = p.plan("assess example.com")
        plan_hi = p.plan("assess example.com", context={"known_targets": ["example.com"]})
        # boosted confidence for at least the scope task
        lo = next(t for t in plan_lo.tasks if t.command.startswith("/scope"))
        hi = next(t for t in plan_hi.tasks if t.command.startswith("/scope"))
        assert hi.confidence >= lo.confidence


# ── goals ──

class TestGoalTracker:
    def _plan(self):
        return Planner().plan("assess example.com")

    def test_completion_pct_zero(self):
        assert GoalTracker(self._plan()).completion_pct() == 0.0

    def test_completion_pct_partial(self):
        plan = self._plan()
        plan.tasks[0].state = TaskState.COMPLETED
        pct = GoalTracker(plan).completion_pct()
        assert 0 < pct < 100

    def test_is_complete(self):
        plan = self._plan()
        for t in plan.tasks:
            t.state = TaskState.COMPLETED
        assert GoalTracker(plan).is_complete()

    def test_current_task_prefers_running(self):
        plan = self._plan()
        plan.tasks[-1].state = TaskState.RUNNING
        assert GoalTracker(plan).current_task().id == plan.tasks[-1].id

    def test_current_task_ready_by_priority(self):
        plan = self._plan()
        # make two ready with different priorities
        plan.tasks[0].state = TaskState.READY
        plan.tasks[0].priority = 3
        plan.tasks[1].state = TaskState.READY
        plan.tasks[1].priority = 9
        assert GoalTracker(plan).current_task().priority == 9

    def test_blocked_detection(self):
        plan = self._plan()
        recon = next(t for t in plan.tasks if t.command.startswith("/recon"))
        scope = next(t for t in plan.tasks if t.command.startswith("/scope"))
        scope.state = TaskState.FAILED
        recon.state = TaskState.WAITING
        blocked = GoalTracker(plan).blocked()
        assert recon in blocked

    def test_confidence_penalised_by_failure(self):
        plan = self._plan()
        base = GoalTracker(plan).confidence()
        plan.tasks[0].state = TaskState.FAILED
        assert GoalTracker(plan).confidence() < base

    def test_snapshot_keys(self):
        snap = GoalTracker(self._plan()).snapshot()
        for key in ("completion_pct", "confidence", "total_tasks", "completed",
                    "remaining", "blocked", "current_task", "revision"):
            assert key in snap


# ── state machine ──

class TestStateMachine:
    def test_initial_idle(self):
        assert AgentStateMachine().state == AgentState.IDLE

    def test_valid_transition(self):
        sm = AgentStateMachine()
        assert sm.transition(AgentState.PLANNING)
        assert sm.state == AgentState.PLANNING

    def test_invalid_transition_rejected(self):
        sm = AgentStateMachine()
        assert not sm.transition(AgentState.REFLECTING)
        assert sm.state == AgentState.IDLE

    def test_can_transition(self):
        sm = AgentStateMachine()
        assert sm.can_transition(AgentState.PLANNING)
        assert not sm.can_transition(AgentState.COMPLETED)

    def test_full_happy_path(self):
        sm = AgentStateMachine()
        for st in (AgentState.PLANNING, AgentState.EXECUTING,
                   AgentState.REFLECTING, AgentState.COMPLETED):
            assert sm.transition(st)

    def test_terminal_reset(self):
        sm = AgentStateMachine()
        sm.transition(AgentState.PLANNING)
        sm.transition(AgentState.FAILED)
        assert sm.is_terminal()
        sm.reset()
        assert sm.state == AgentState.IDLE

    def test_observer_called(self):
        sm = AgentStateMachine()
        seen = []
        sm.on_change(lambda a, b: seen.append((a, b)))
        sm.transition(AgentState.PLANNING)
        assert seen == [(AgentState.IDLE, AgentState.PLANNING)]

    def test_observer_exception_isolated(self):
        sm = AgentStateMachine()
        sm.on_change(lambda a, b: (_ for _ in ()).throw(RuntimeError("boom")))
        assert sm.transition(AgentState.PLANNING)  # does not raise

    def test_emit_via_bus(self):
        from hydra.services.event_bus import EventBus
        bus = EventBus()
        events = []
        bus.subscribe("agent.state", lambda e: events.append(e.payload))
        sm = AgentStateMachine(event_bus=bus)
        sm.transition(AgentState.PLANNING)
        assert events and events[0]["to"] == "planning"

    def test_force_bypasses_validation(self):
        sm = AgentStateMachine()
        sm.force(AgentState.REFLECTING)
        assert sm.state == AgentState.REFLECTING

    def test_thread_safety(self):
        sm = AgentStateMachine()
        errors = []

        def worker():
            try:
                for _ in range(200):
                    sm.can_transition(AgentState.PLANNING)
                    sm.transition(AgentState.PLANNING)
                    sm.force(AgentState.IDLE)
            except Exception as e:  # pragma: no cover
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors
