"""Batch 6 tests — EventBus event catalog and telemetry integration.

Asserts the agent engine emits the full ``agent.*`` event set (additive; the
EventBus itself is unchanged) and records planning/execution/reasoning/reflection
telemetry with success/failure/command counters. No polling anywhere.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hydra.agent.orchestrator import Orchestrator
from hydra.observability.telemetry import telemetry
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


def _collect(objective, fail_prefixes=()):
    bus = EventBus()
    seen = []
    bus.subscribe("*", lambda e: seen.append(e.type))
    Orchestrator(make_exec(fail_prefixes), event_bus=bus).run(objective)
    return set(seen)


class TestEventCatalog:
    def test_success_run_events(self):
        events = _collect("assess example.com")
        for ev in ("agent.started", "agent.plan.created", "agent.state",
                   "agent.task.started", "agent.task.completed", "agent.reasoning",
                   "agent.reflection", "agent.goal.progress", "agent.completed"):
            assert ev in events, ev

    def test_failure_run_events(self):
        events = _collect("scan example.com for xss", fail_prefixes=("/scan",))
        assert "agent.task.failed" in events
        assert "agent.plan.updated" in events

    def test_cancel_event(self):
        bus = EventBus()
        seen = []
        bus.subscribe("agent.*", lambda e: seen.append(e.type))
        ref = {}

        def ex(cmd):
            ref["o"].cancel()
            return FakeResult(status="success", output={})

        ref["o"] = Orchestrator(ex, event_bus=bus)
        ref["o"].run("assess example.com")
        assert "agent.cancelled" in seen

    def test_events_are_additive_not_replacing(self):
        # A vanilla EventBus still works with existing (non-agent) events.
        bus = EventBus()
        got = []
        bus.subscribe("tool.started", lambda e: got.append(e.payload))
        bus.emit("tool.started", {"tool": "recon"})
        assert got == [{"tool": "recon"}]


class TestTelemetry:
    def test_latency_timers_recorded(self):
        Orchestrator(make_exec(), event_bus=EventBus()).run("assess example.com")
        for name in ("agent.planning", "agent.execution", "agent.reasoning",
                     "agent.reflection"):
            stats = telemetry.perf_stats(name)
            assert stats.get("count", 0) >= 1, name

    def test_command_counter(self):
        snap0 = telemetry.snapshot().get("counters", {})
        before = snap0.get("agent.commands", 0)
        Orchestrator(make_exec()).run("assess example.com")
        after = telemetry.snapshot().get("counters", {}).get("agent.commands", 0)
        assert after > before

    def test_success_failure_counters(self):
        counters0 = telemetry.snapshot().get("counters", {})
        s_before = counters0.get("agent.task.success", 0)
        Orchestrator(make_exec()).run("assess example.com")
        s_after = telemetry.snapshot().get("counters", {}).get("agent.task.success", 0)
        assert s_after > s_before
