"""Batch 5 tests — session, orchestrator, service, container registration."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any

from hydra.agent.memory import AgentMemory
from hydra.agent.models import AgentState, ExecutionPlan, Goal, TaskState
from hydra.agent.orchestrator import Orchestrator
from hydra.agent.service import AgentService
from hydra.agent.session import AgentSession
from hydra.services import ServiceContainer
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


# ── Session ──

class TestSession:
    def _session(self):
        plan = ExecutionPlan(goal=Goal(objective="assess a.com", target="a.com"))
        return AgentSession(objective="assess a.com", plan=plan, memory=AgentMemory(session_id="s1"))

    def test_roundtrip(self):
        s = self._session()
        s.memory.set("k", "v")
        s.status = "completed"
        r = AgentSession.from_dict(s.to_dict())
        assert r.id == s.id and r.status == "completed"
        assert r.memory.get("k") == "v"

    def test_summary(self):
        s = self._session()
        summ = s.summary()
        assert summ["objective"] == "assess a.com" and "state" in summ


# ── Orchestrator ──

class TestOrchestrator:
    def test_run_completes(self):
        ex = make_exec()
        orch = Orchestrator(ex, event_bus=EventBus())
        session = orch.run("assess example.com")
        assert session.status == "completed"
        assert session.state == AgentState.COMPLETED
        assert all(t.state == TaskState.COMPLETED for t in session.plan.tasks)

    def test_dependency_order(self):
        ex = make_exec()
        Orchestrator(ex).run("assess example.com")
        cmds = ex.calls  # type: ignore[attr-defined]
        # scope before recon before any scan
        assert cmds.index("/scope example.com") < cmds.index("/recon example.com")
        recon_i = cmds.index("/recon example.com")
        first_scan = min(i for i, c in enumerate(cmds) if c.startswith("/scan"))
        assert recon_i < first_scan

    def test_emits_lifecycle_events(self):
        bus = EventBus()
        seen = []
        bus.subscribe("agent.*", lambda e: seen.append(e.type))
        Orchestrator(make_exec(), event_bus=bus).run("assess example.com")
        for ev in ("agent.started", "agent.plan.created", "agent.goal.progress",
                   "agent.completed"):
            assert ev in seen

    def test_failure_recovers_via_alternative(self):
        # /scan always fails → retries then ALTERNATIVE (/recon) which succeeds.
        ex = make_exec(fail_prefixes=("/scan",))
        session = Orchestrator(ex).run("scan example.com for xss")
        assert session.status in ("completed", "failed")
        # the run terminates (bounded) and produced an alternative /recon call
        assert any(c == "/recon example.com" for c in ex.calls)  # type: ignore[attr-defined]

    def test_max_iterations_bound(self):
        ex = make_exec(fail_prefixes=("/",))  # everything fails
        orch = Orchestrator(ex)
        orch.set_max_iterations(3)
        session = orch.run("assess example.com")
        assert session.state in (AgentState.FAILED, AgentState.COMPLETED)

    def test_cancel_during_run(self):
        orch_ref = {}

        def ex(cmd):
            # cancel after the first command executes
            orch_ref["o"].cancel()
            return FakeResult(status="success", output={})

        orch = Orchestrator(ex)
        orch_ref["o"] = orch
        session = orch.run("assess example.com")
        assert session.status == "cancelled"
        assert session.state == AgentState.CANCELLED
        assert any(t.state == TaskState.CANCELLED for t in session.plan.tasks)

    def test_status_before_run(self):
        orch = Orchestrator(make_exec())
        assert orch.status()["status"] == "idle"

    def test_telemetry_counters(self):
        from hydra.observability.telemetry import telemetry
        before = telemetry.snapshot().get("counters", {}).get("agent.commands", 0)
        Orchestrator(make_exec()).run("assess example.com")
        after = telemetry.snapshot().get("counters", {}).get("agent.commands", 0)
        assert after > before

    def test_resume_completes_remaining(self):
        # Build a plan where scope already completed; resume runs the rest.
        from hydra.agent.planner import Planner
        plan = Planner().plan("assess example.com")
        plan.tasks[0].state = TaskState.COMPLETED  # scope done
        session = AgentSession(objective="assess example.com", plan=plan,
                               memory=AgentMemory())
        ex = make_exec()
        result = Orchestrator(ex).resume(session)
        assert result.status == "completed"
        assert "/scope example.com" not in ex.calls  # type: ignore[attr-defined]


# ── Service ──

class TestAgentService:
    def _svc(self, tmp_path):
        return AgentService(EventBus(), tmp_path)

    def test_run_stores_session(self, tmp_path):
        svc = self._svc(tmp_path)
        session = svc.run("assess example.com", make_exec())
        assert svc.get_session(session.id) is session
        assert session.status == "completed"

    def test_list_sessions(self, tmp_path):
        svc = self._svc(tmp_path)
        svc.run("assess a.com", make_exec())
        svc.run("assess b.com", make_exec())
        assert len(svc.list_sessions()) == 2

    def test_cancel_unknown(self, tmp_path):
        assert self._svc(tmp_path).cancel("nope") is False

    def test_cancel_known(self, tmp_path):
        svc = self._svc(tmp_path)
        session = svc.run("assess example.com", make_exec())
        # after completion the orchestrator is still tracked → cancel returns True
        assert svc.cancel(session.id) is True

    def test_save_and_load_session(self, tmp_path):
        svc = self._svc(tmp_path)
        session = svc.run("assess example.com", make_exec())
        loaded = svc.load_session(session.id)
        assert loaded is not None and loaded.id == session.id
        assert loaded.objective == "assess example.com"

    def test_resume_from_disk(self, tmp_path):
        svc = self._svc(tmp_path)
        session = svc.run("assess example.com", make_exec())
        svc2 = AgentService(EventBus(), tmp_path)  # fresh service (restart)
        resumed = svc2.resume(session.id, make_exec())
        assert resumed is not None and resumed.id == session.id

    def test_stats_and_health(self, tmp_path):
        svc = self._svc(tmp_path)
        svc.run("assess example.com", make_exec())
        assert svc.get_stats()["sessions"] == 1
        assert svc.get_health()["status"] == "ok"

    def test_emits_session_events(self, tmp_path):
        bus = EventBus()
        seen = []
        bus.subscribe("agent.session.*", lambda e: seen.append(e.type))
        AgentService(bus, tmp_path).run("assess example.com", make_exec())
        assert "agent.session.started" in seen
        assert "agent.session.finished" in seen


# ── ServiceContainer registration ──

class TestContainerRegistration:
    def test_agent_engine_registered(self):
        c = ServiceContainer(event_bus=EventBus())
        assert isinstance(c.agent_engine, AgentService)

    def test_distinct_from_swarm_agents(self):
        c = ServiceContainer(event_bus=EventBus())
        # existing swarm service still resolves and is a different class
        assert c.agents.__class__.__name__ == "AgentService"
        assert c.agents.__class__ is not c.agent_engine.__class__
        assert type(c.agent_engine).__module__ == "hydra.agent.service"

    def test_lazy_cached(self):
        c = ServiceContainer(event_bus=EventBus())
        assert c.agent_engine is c.agent_engine


# ── Thread safety of a run ──

def test_concurrent_runs(tmp_path):
    svc = AgentService(EventBus(), tmp_path)
    errors = []

    def worker(i):
        try:
            svc.run(f"assess host{i}.com", make_exec())
        except Exception as e:  # pragma: no cover
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    time.sleep(0.05)
    assert not errors
    assert len(svc.list_sessions()) == 5
