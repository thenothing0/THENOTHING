"""Batch 7 tests — Textual integration (event bridge, renderers, app flow)."""

from __future__ import annotations

import pytest

textual = pytest.importorskip("textual")

from unittest.mock import MagicMock

from control_center.tui.event_bridge import (
    AgentGoalProgress,
    AgentPlanReady,
    AgentReasoning,
    AgentRunFinished,
    AgentStarted,
    AgentTaskUpdate,
    EventBridge,
)
from control_center.tui.widgets import markdown_renderer as mr
from hydra.services.event_bus import EventBus


def _posted(app):
    return [c.args[0] for c in app.post_message.call_args_list]


# ── Event bridge translation ──

class TestBridgeAgentEvents:
    def _bridge(self):
        app = MagicMock()
        bus = EventBus()
        bridge = EventBridge(app, bus)
        bridge.connect()
        return app, bus

    def test_agent_started(self):
        app, bus = self._bridge()
        bus.emit("agent.started", {"objective": "assess a.com", "target": "a.com", "session_id": "s"})
        msgs = [m for m in _posted(app) if isinstance(m, AgentStarted)]
        assert msgs and msgs[0].objective == "assess a.com" and msgs[0].target == "a.com"

    def test_agent_plan_created(self):
        app, bus = self._bridge()
        bus.emit("agent.plan.created", {"session_id": "s", "tasks": 5, "revision": 0})
        msgs = [m for m in _posted(app) if isinstance(m, AgentPlanReady)]
        assert msgs and msgs[0].tasks == 5

    def test_agent_reasoning(self):
        app, bus = self._bridge()
        bus.emit("agent.reasoning", {"phase": "plan", "thought": "thinking"})
        msgs = [m for m in _posted(app) if isinstance(m, AgentReasoning)]
        assert msgs and msgs[0].thought == "thinking"

    def test_agent_goal_progress(self):
        app, bus = self._bridge()
        bus.emit("agent.goal.progress", {"completion_pct": 50})
        msgs = [m for m in _posted(app) if isinstance(m, AgentGoalProgress)]
        assert msgs and msgs[0].payload["completion_pct"] == 50

    def test_agent_task_updates(self):
        app, bus = self._bridge()
        bus.emit("agent.task.completed", {"command": "/recon a.com", "description": "d"})
        bus.emit("agent.task.failed", {"command": "/scan a.com xss"})
        msgs = [m for m in _posted(app) if isinstance(m, AgentTaskUpdate)]
        states = {m.state for m in msgs}
        assert "completed" in states and "failed" in states

    def test_agent_completed_and_cancelled(self):
        app, bus = self._bridge()
        bus.emit("agent.completed", {"status": "completed", "session_id": "s"})
        bus.emit("agent.cancelled", {"session_id": "s"})
        msgs = [m for m in _posted(app) if isinstance(m, AgentRunFinished)]
        statuses = {m.status for m in msgs}
        assert "completed" in statuses and "cancelled" in statuses

    def test_existing_events_still_translate(self):
        # additive: a pre-existing event type still yields its message
        from control_center.tui.event_bridge import ToolStarted
        app, bus = self._bridge()
        bus.emit("tool.started", {"tool": "recon", "target": "a.com"})
        assert any(isinstance(m, ToolStarted) for m in _posted(app))


# ── markdown_renderer agent helpers ──

class TestAgentRenderers:
    def test_agent_started_renderable(self):
        r = mr.agent_started("assess a.com", "a.com")
        assert r is not None

    def test_plan_tree_builds(self):
        tasks = [
            {"id": "1", "command": "/scope a.com", "state": "completed", "depends_on": []},
            {"id": "2", "command": "/recon a.com", "state": "running", "depends_on": ["1"]},
            {"id": "3", "command": "/scan a.com xss", "state": "waiting", "depends_on": ["2"]},
        ]
        tree = mr.agent_plan_tree(tasks, "a.com")
        # root has one child (scope) which has recon which has scan
        assert len(tree.children) == 1
        assert len(tree.children[0].children) == 1

    def test_reasoning_renderable(self):
        assert mr.agent_reasoning("plan", "thought") is not None

    def test_task_line_renderable(self):
        assert mr.agent_task_line("completed", "/recon a.com") is not None

    def test_progress_panel(self):
        snap = {"objective": "o", "state": "executing", "completion_pct": 40,
                "confidence": 0.6, "current_task": "recon", "completed": 2,
                "total_tasks": 5, "blocked": 0}
        assert mr.agent_progress(snap) is not None

    def test_finished_renderable(self):
        assert mr.agent_finished("completed", {"completion_pct": 100}) is not None
        assert mr.agent_finished("failed", None) is not None

    def test_task_icons(self):
        assert mr._task_icon("completed") != mr._task_icon("failed")
        assert mr._task_icon("unknown-state")  # falls back


# ── App-level /agent flow (headless) ──

class TestAppAgentFlow:
    async def _run(self, fn):
        from control_center.app import HydraApp
        app = HydraApp()
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await fn(app, pilot)

    def test_agent_usage_message(self):
        import asyncio

        async def body(app, pilot):
            app.run_command("/agent")  # no objective
            await pilot.pause()
            # no worker should be dispatched for empty objective
            assert not any(w.name and w.name.startswith("agent-") for w in app.workers)

        asyncio.run(self._run(body))

    def test_agent_dispatch_creates_worker(self):
        import asyncio

        async def body(app, pilot):
            seen = []
            app._event_bus.subscribe("agent.*", lambda e: seen.append(e.type))
            app.run_command("/agent assess example.com")
            # wait for the run to FINISH so the worker isn't mid-flight at teardown
            for _ in range(80):
                await pilot.pause(0.25)
                if "agent.completed" in seen or "agent.cancelled" in seen:
                    break
            assert "agent.started" in seen
            assert "agent.completed" in seen or "agent.cancelled" in seen

        asyncio.run(self._run(body))

    def test_context_drawer_show_agent(self):
        import asyncio

        async def body(app, pilot):
            drawer = app.query_one("#drawer")
            drawer.show_agent({"objective": "o", "state": "executing",
                               "completion_pct": 50, "confidence": 0.7,
                               "current_task": "recon", "completed": 1,
                               "total_tasks": 4, "failed": 0, "blocked": 0})
            await pilot.pause()
            assert drawer.has_class("open")

        asyncio.run(self._run(body))
