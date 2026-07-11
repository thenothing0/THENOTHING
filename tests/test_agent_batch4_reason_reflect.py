"""Batch 4 tests — reasoner and reflection engine."""

from __future__ import annotations

from hydra.agent.models import Observation, ReflectionAction, Task, TaskState
from hydra.agent.reasoner import Reasoner
from hydra.agent.reflection import ReflectionEngine
from hydra.services.event_bus import EventBus


# ── Reasoner ──

class TestReasoner:
    def test_note_records(self):
        r = Reasoner()
        step = r.note("plan", "hello")
        assert step.phase == "plan" and step.thought == "hello"
        assert r.steps() == [step]

    def test_log_bounded(self):
        r = Reasoner(max_log=10)
        for i in range(25):
            r.note("x", f"m{i}")
        assert len(r.steps()) == 10
        assert r.steps()[-1].thought == "m24"

    def test_observe_returns_observation_and_notes(self):
        r = Reasoner()
        obs = r.observe("recon", {"subdomains": [1, 2, 3]})
        assert isinstance(obs, Observation)
        assert obs.source == "recon"
        # a grounded note was added
        assert any(s.phase == "observe" for s in r.steps())

    def test_summarize_variants(self):
        assert Reasoner.summarize(None) == "no data"
        assert "keys" in Reasoner.summarize({"a": 1, "b": 2})
        assert Reasoner.summarize([1, 2, 3]) == "3 item(s)"
        assert Reasoner.summarize("hi") == "hi"

    def test_think_plan_grounded(self):
        r = Reasoner()
        step = r.think_plan("assess example.com", "example.com", 5)
        assert "5 task" in step.thought and "example.com" in step.thought

    def test_think_execute(self):
        step = Reasoner().think_execute("/recon a.com")
        assert "/recon a.com" in step.thought

    def test_think_reflect(self):
        step = Reasoner().think_reflect("scan a.com", True, "continue")
        assert "succeeded" in step.thought

    def test_recent(self):
        r = Reasoner()
        for i in range(30):
            r.note("x", f"m{i}")
        assert len(r.recent(5)) == 5

    def test_clear(self):
        r = Reasoner()
        r.note("x", "m")
        r.clear()
        assert r.steps() == []

    def test_emits_event(self):
        bus = EventBus()
        seen = []
        bus.subscribe("agent.reasoning", lambda e: seen.append(e.payload))
        Reasoner(event_bus=bus).note("plan", "thinking")
        assert seen and seen[0]["thought"] == "thinking"


# ── Reflection ──

class TestReflection:
    def test_success_non_empty_continue(self):
        t = Task(description="d", command="/status", state=TaskState.COMPLETED,
                 result={"type": "status"})
        ref = ReflectionEngine().reflect(t)
        assert ref.success and ref.action == ReflectionAction.CONTINUE
        assert not ref.missing_info

    def test_success_empty_missing_info(self):
        t = Task(description="d", command="/search x", state=TaskState.COMPLETED,
                 result=[])
        ref = ReflectionEngine().reflect(t)
        assert ref.action == ReflectionAction.CONTINUE and ref.missing_info

    def test_failed_retry(self):
        t = Task(description="d", command="/recon a.com", state=TaskState.FAILED,
                 attempts=1, max_attempts=3, error="boom")
        ref = ReflectionEngine().reflect(t)
        assert ref.action == ReflectionAction.RETRY and not ref.success

    def test_failed_scan_alternative_recon(self):
        t = Task(description="d", command="/scan a.com xss", state=TaskState.FAILED,
                 attempts=3, max_attempts=3)
        ref = ReflectionEngine().reflect(t)
        assert ref.action == ReflectionAction.ALTERNATIVE
        assert ref.alternative_command == "/recon a.com"

    def test_failed_attack_alternative_scan(self):
        t = Task(description="d", command="/attack a.com --classes=xss",
                 state=TaskState.FAILED, attempts=3, max_attempts=3)
        ref = ReflectionEngine().reflect(t)
        assert ref.action == ReflectionAction.ALTERNATIVE
        assert ref.alternative_command == "/scan a.com xss"

    def test_failed_recon_abort(self):
        t = Task(description="d", command="/recon a.com", state=TaskState.FAILED,
                 attempts=3, max_attempts=3)
        ref = ReflectionEngine().reflect(t)
        assert ref.action == ReflectionAction.ABORT

    def test_cancelled_abort(self):
        t = Task(description="d", command="/scan a.com xss", state=TaskState.CANCELLED)
        ref = ReflectionEngine().reflect(t)
        assert ref.action == ReflectionAction.ABORT and not ref.success

    def test_result_arg_overrides(self):
        t = Task(description="d", command="/status", state=TaskState.COMPLETED)
        ref = ReflectionEngine().reflect(t, result={"ok": 1})
        assert not ref.missing_info

    def test_emits_event(self):
        bus = EventBus()
        seen = []
        bus.subscribe("agent.reflection", lambda e: seen.append(e.payload))
        t = Task(description="d", command="/status", state=TaskState.COMPLETED, result={"x": 1})
        ReflectionEngine(event_bus=bus).reflect(t)
        assert seen and seen[0]["action"] == "continue"
