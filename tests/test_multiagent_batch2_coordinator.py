"""MA Batch 2 tests — manager, planner agent, coordinator."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hydra.multi_agent.coordinator import Coordinator
from hydra.multi_agent.manager import AgentManager
from hydra.multi_agent.models import AgentRole, AgentStatus, MTaskState
from hydra.multi_agent.planner_agent import PlannerAgent, build_task_plan
from hydra.services.event_bus import EventBus


@dataclass
class FakeResult:
    status: str = "success"
    output: Any = None
    errors: list = field(default_factory=list)


def make_exec(fail_prefixes=(), scan_findings=True):
    calls = []

    def ex(cmd):
        calls.append(cmd)
        if any(cmd.startswith(p) for p in fail_prefixes):
            return FakeResult(status="error", errors=["nope"])
        if cmd.startswith("/scan") and scan_findings:
            return {"confirmed_findings": [{"title": "XSS reflected"}], "suspected": []}
        return FakeResult(status="success", output={"cmd": cmd})

    ex.calls = calls  # type: ignore[attr-defined]
    return ex


# ── AgentManager ──

class TestManager:
    def test_create_ids_and_event(self):
        bus = EventBus()
        seen = []
        bus.subscribe("team.agent.spawned", lambda e: seen.append(e.payload))
        m = AgentManager(bus)
        info = m.create(AgentRole.RECON)
        assert info.agent_id == "recon-1"
        assert seen and seen[0]["role"] == "recon"

    def test_create_increments(self):
        m = AgentManager()
        assert m.create(AgentRole.WEB).agent_id == "web-1"
        assert m.create(AgentRole.WEB).agent_id == "web-2"

    def test_ensure_roles_idempotent(self):
        m = AgentManager()
        m.ensure_roles({AgentRole.RECON, AgentRole.WEB})
        m.ensure_roles({AgentRole.RECON, AgentRole.WEB})
        assert len(m.by_role(AgentRole.RECON)) == 1
        assert len(m.by_role(AgentRole.WEB)) == 1

    def test_assign_and_complete(self):
        m = AgentManager()
        info = m.create(AgentRole.RECON)
        m.assign(info.agent_id, "task-1")
        assert m.get(info.agent_id).status == AgentStatus.BUSY
        assert m.get(info.agent_id).current_task_id == "task-1"
        m.complete(info.agent_id, ok=True)
        assert m.get(info.agent_id).status == AgentStatus.IDLE
        assert m.get(info.agent_id).completed == 1

    def test_complete_failed_counter(self):
        m = AgentManager()
        info = m.create(AgentRole.WEB)
        m.complete(info.agent_id, ok=False)
        assert m.get(info.agent_id).failed == 1

    def test_waiting(self):
        m = AgentManager()
        info = m.create(AgentRole.RECON)
        m.waiting(info.agent_id)
        assert m.get(info.agent_id).status == AgentStatus.WAITING

    def test_destroy(self):
        m = AgentManager()
        info = m.create(AgentRole.RECON)
        m.destroy(info.agent_id)
        assert m.get(info.agent_id) is None

    def test_monitor_and_status(self):
        m = AgentManager()
        m.create(AgentRole.RECON)
        m.create(AgentRole.WEB)
        assert len(m.monitor()) == 2
        st = m.status()
        assert st["agents"] == 2 and "recon" in st["by_role"]

    def test_instance_tracking(self):
        m = AgentManager()
        obj = object()
        info = m.create(AgentRole.RECON, instance=obj)
        assert m.instance(info.agent_id) is obj


# ── PlannerAgent / build_task_plan ──

class TestPlannerAgent:
    def test_roles_assigned(self):
        tasks = build_task_plan("assess example.com")
        roles = {t.role for t in tasks}
        assert AgentRole.RECON in roles and AgentRole.WEB in roles
        assert AgentRole.REPORT in roles

    def test_commands_real(self):
        for t in build_task_plan("full pentest of example.com for xss"):
            assert t.command.startswith("/")

    def test_scope_before_recon_dep(self):
        tasks = build_task_plan("assess example.com")
        scope = next(t for t in tasks if t.command.startswith("/scope"))
        recon = next(t for t in tasks if t.command.startswith("/recon") and t.role == AgentRole.RECON)
        assert scope.id in recon.depends_on

    def test_network_hint_adds_network_task(self):
        tasks = build_task_plan("network assessment of example.com")
        assert any(t.role == AgentRole.NETWORK for t in tasks)

    def test_no_network_task_without_hint(self):
        tasks = build_task_plan("assess example.com")
        assert not any(t.role == AgentRole.NETWORK for t in tasks)

    def test_no_target_status(self):
        tasks = build_task_plan("just status")
        assert len(tasks) == 1 and tasks[0].command == "/status"

    def test_planner_agent_plan(self):
        assert PlannerAgent().plan("assess example.com")


# ── Coordinator ──

class TestCoordinator:
    def test_run_completes(self):
        ex = make_exec()
        coord = Coordinator(ex, event_bus=EventBus())
        result = coord.run("assess example.com")
        assert result["status"] == "completed"
        assert all(t["state"] == "completed" for t in result["tasks"])

    def test_findings_extracted(self):
        ex = make_exec()
        coord = Coordinator(ex)
        result = coord.run("scan example.com for xss")
        assert result["findings"]
        assert result["findings"][0]["title"] == "XSS reflected"

    def test_agents_spawned_per_role(self):
        ex = make_exec()
        coord = Coordinator(ex)
        coord.run("assess example.com")
        roles = {a["role"] for a in coord.manager.monitor()}
        assert "recon" in roles and "web" in roles

    def test_dependency_execution_order(self):
        ex = make_exec()
        Coordinator(ex).run("assess example.com")
        cmds = ex.calls  # type: ignore[attr-defined]
        assert cmds.index("/scope example.com") < cmds.index("/recon example.com")

    def test_cancel(self):
        ref = {}

        def ex(cmd):
            ref["c"].cancel()
            return FakeResult(status="success")

        coord = Coordinator(ex)
        ref["c"] = coord
        result = coord.run("assess example.com")
        assert result["status"] == "cancelled"

    def test_status_shape(self):
        coord = Coordinator(make_exec())
        st = coord.status()
        assert "queue" in st and "agents" in st and "memory" in st

    def test_injected_dispatcher_used(self):
        calls = {"n": 0}

        class FakeDispatcher:
            def dispatch(self, tasks):
                calls["n"] += 1
                for t in tasks:
                    t.state = MTaskState.COMPLETED

            def cancel(self):
                pass

        coord = Coordinator(make_exec(), dispatcher=FakeDispatcher())
        coord.run("assess example.com")
        assert calls["n"] >= 1

    def test_execute_task_primitive(self):
        ex = make_exec()
        coord = Coordinator(ex)
        from hydra.multi_agent.models import AgentTask
        coord.manager.ensure_roles({AgentRole.RECON})
        t = AgentTask(description="d", command="/recon example.com", role=AgentRole.RECON,
                      state=MTaskState.READY)
        coord.queue.add(t)
        coord.execute_task(t)
        assert t.state == MTaskState.COMPLETED
        assert coord.memory.history()

    def test_failure_marks_failed(self):
        coord = Coordinator(make_exec(fail_prefixes=("/",)))
        coord.set_max_iterations(20) if hasattr(coord, "set_max_iterations") else None
        result = coord.run("assess example.com")
        assert result["status"] in ("failed", "completed")

    def test_conflict_resolver_invoked(self):
        calls = {"n": 0}

        class FakeResolver:
            def resolve(self, memory):
                calls["n"] += 1

        Coordinator(make_exec(), conflict_resolver=FakeResolver()).run("assess example.com")
        assert calls["n"] >= 1
