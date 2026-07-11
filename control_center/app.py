"""HydraApp — the chat-first HYDRA terminal (Textual).

Layout: HeaderBar (top) · ChatView (fills) · CommandInput (prompt) · StatusBar
(bottom). SessionSidebar / TaskPanel are collapsible; NotificationCenter,
Inspector and ContextDrawer are overlays — all hidden by default.

The App owns routing, layout, worker dispatch, keybindings and the single 1s
monitor refresh. All rendering lives in widgets (via ``markdown_renderer``); all
orchestration stays in the frozen backend (Facade / services / EventBus).
"""

from __future__ import annotations

import os
import uuid

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.worker import Worker, WorkerState

from control_center.tui.event_bridge import (
    AgentGoalProgress,
    AgentPlanReady,
    AgentReasoning,
    AgentRunFinished,
    AgentSpawned,
    AgentStarted,
    AgentTaskCompleted,
    AgentTaskUpdate,
    AIToken,
    EventBridge,
    FindingCreated,
    FindingTransitioned,
    HydraEvent,
    ToolCompleted,
    ToolFailed,
    ToolOutputChunk,
    ToolStarted,
    WorkflowAdvanced,
)
from control_center.tui.state import WorkspaceState
from control_center.tui.themes.native import (
    DEFAULT_THEME,
    HYDRA_THEMES,
    register_hydra_themes,
    resolve_theme,
)
from control_center.tui.widgets.chat_view import ChatView
from control_center.tui.widgets.command_input import CommandInput, CommandSubmitted
from control_center.tui.widgets.command_palette import HydraCommandProvider
from control_center.tui.widgets.context_drawer import ContextDrawer
from control_center.tui.widgets.header_bar import HeaderBar
from control_center.tui.widgets.inspector import Inspector
from control_center.tui.widgets import markdown_renderer as mr
from control_center.tui.widgets.notification_center import NotificationCenter
from control_center.tui.widgets.session_sidebar import NavSelected, SessionSidebar
from control_center.tui.widgets.status_bar import StatusBar
from control_center.tui.widgets.task_panel import TaskPanel

from hydra.commands.builtins import register_all_builtins
from hydra.commands.registry import CommandRegistry
from hydra.facade import HydraFacade
from hydra.presentation.api import PresentationAPI
from hydra.registry.capability import CapabilityRegistry
from hydra.services import ServiceContainer
from hydra.services.event_bus import EventBus

# notify() accepts only these severities; the NotificationCenter keeps richer ones.
_NOTIFY_SEVERITIES = {"information", "warning", "error"}


class HydraApp(App):
    """HYDRA Terminal UI — chat-first cognitive red team console."""

    TITLE = "HYDRA"
    SUB_TITLE = "v2.0"

    CSS_PATH = "tui/app.tcss"
    COMMANDS = {HydraCommandProvider}
    COMMAND_PALETTE_BINDING = "ctrl+p"

    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit", priority=True),
        Binding("ctrl+c", "cancel_task", "Cancel task", priority=True),
        Binding("ctrl+p", "command_palette", "Palette", priority=True),
        Binding("ctrl+k", "command_palette", "Palette", priority=True, show=False),
        Binding("ctrl+l", "clear_log", "Clear", show=False),
        Binding("ctrl+t", "new_session", "New session", show=False),
        Binding("ctrl+b", "toggle_sidebar", "Sidebar", show=False),
        Binding("ctrl+j", "toggle_tasks", "Tasks", show=False),
        Binding("ctrl+n", "toggle_notifications", "Notifications", show=False),
        Binding("f2", "cycle_theme", "Theme", show=False),
        Binding("escape", "close_overlays", "Close", show=False),
    ]

    def __init__(self, resume_session: str | None = None):
        super().__init__()
        self._resume_session = resume_session
        self._restored = False

        self._event_bus = EventBus()
        self._capability_registry = CapabilityRegistry()
        self._services = ServiceContainer(event_bus=self._event_bus)
        self._command_registry = CommandRegistry()

        register_all_builtins(self._command_registry, self._capability_registry)

        self._facade = HydraFacade(
            self._services,
            self._capability_registry,
            self._event_bus,
            self._command_registry,
        )
        self.api = PresentationAPI(
            self._facade,
            self._capability_registry,
            self._event_bus,
        )

        self._bridge: EventBridge | None = None

        self._theme_name = DEFAULT_THEME
        try:
            from hydra.config import ConfigManager
            cfg = ConfigManager.get()
            self._theme_name = cfg.get_value("tui.theme", DEFAULT_THEME)
        except Exception:
            pass

    # ── Convenience accessors ──

    @property
    def facade(self) -> HydraFacade:
        return self._facade

    # ── State init ──

    def _init_state(self) -> WorkspaceState:
        recovery = self._services.session.check_crash_recovery()
        if recovery and not self._resume_session:
            self._resume_session = recovery.get("session_id")

        if self._resume_session:
            data = self._services.session.load(self._resume_session)
            if data:
                self._restored = True
                return WorkspaceState.from_dict(data)

        state = WorkspaceState()
        state.session_id = f"session-{uuid.uuid4().hex[:8]}"
        state.theme = self._theme_name
        state.sidebar_visible = False  # chat-first: hidden on a fresh launch
        return state

    # ── Compose ──

    def compose(self) -> ComposeResult:
        yield HeaderBar(id="header")
        with Horizontal(id="body"):
            yield SessionSidebar(id="sidebar")
            with Vertical(id="center"):
                yield ChatView(id="conversation")
                yield CommandInput(id="input")
        yield TaskPanel(id="tasks")
        yield StatusBar(id="status")
        yield NotificationCenter(id="notifications")
        yield Inspector(id="inspector")
        yield ContextDrawer(id="drawer")

    def on_mount(self) -> None:
        self.state = self._init_state()

        register_hydra_themes(self)
        try:
            self.theme = resolve_theme(self.state.theme or self._theme_name)
        except Exception:
            self.theme = DEFAULT_THEME
        # Normalise the stored id to the resolved native theme name.
        self.state.theme = self.theme

        self._bridge = EventBridge(self, self._event_bus)
        self._bridge.connect()

        if self.state.session_id:
            self._services.session.write_sentinel(self.state.session_id)

        try:
            from hydra.config import ConfigManager
            cfg = ConfigManager.get()
            auto = cfg.get_value("session.auto_save", True)
            auto_interval = cfg.get_value("auto_save_interval", 30)
        except Exception:
            auto, auto_interval = True, 30
        if auto:
            self._services.session.start_auto_save(
                interval=auto_interval, state_callback=lambda: self.state.to_dict())

        cmd_input = self.query_one("#input", CommandInput)
        cmd_input.set_completion_provider(self._provide_completions)
        cmd_input.set_completions([c.name for c in self.api.list_commands()])
        cmd_input.focus()

        self._restore_conversation()
        self._apply_panel_state()
        self._refresh_sidebar()

        # The single allowed timer: 1s monitor refresh.
        self.set_interval(1.0, self._refresh_metrics)

    def on_unmount(self) -> None:
        if self._bridge:
            self._bridge.disconnect()
        self._services.session.stop_auto_save()
        self._services.session.clear_sentinel()
        try:
            self.query_one("#input", CommandInput).save_history()
        except Exception:
            pass
        if getattr(self, "state", None) and self.state.session_id:
            self._services.session.save(self.state.session_id, self.state.to_dict())

    # ── Restore helpers ──

    def _restore_conversation(self) -> None:
        if not self.state.conversation_entries:
            return
        log = self.query_one("#conversation", ChatView)
        for entry in self.state.conversation_entries:
            etype = entry.get("entry_type", "")
            if etype == "user":
                log.add_user_input(entry.get("text", ""))
            elif etype == "system":
                log.add_system(entry.get("text", ""))
            elif etype == "error":
                log.add_error(entry.get("text", ""))
            elif etype == "result":
                log.add_result(entry.get("data", {}))
        log.add_system("(Session restored)")

    def _apply_panel_state(self) -> None:
        sidebar = self.query_one("#sidebar", SessionSidebar)
        sidebar.set_class(bool(self._restored and self.state.sidebar_visible), "visible")
        self.query_one("#tasks", TaskPanel).set_class(self.state.task_panel_open, "visible")

    # ── Completion provider ──

    def _provide_completions(self, text: str) -> list[str]:
        partial = text.lstrip("/").split()[0] if text.startswith("/") else ""
        return self._facade.complete_command(partial)

    # ── Command handling ──

    def on_command_submitted(self, event: CommandSubmitted) -> None:
        self.run_command(event.value)

    def run_command(self, text: str) -> None:
        """Execute a command/message exactly as if typed at the prompt."""
        text = (text or "").strip()
        if not text:
            return
        log = self.query_one("#conversation", ChatView)
        log.add_user_input(text)
        self.state.conversation_entries.append({"entry_type": "user", "text": text})

        if text.startswith("/agent"):
            self._dispatch_agent(text)
            return

        if text.startswith("/"):
            partial = text[1:].split()[0] if text[1:] else ""
            self.query_one("#input", CommandInput).set_completions(
                self._facade.complete_command(partial))
            if text.startswith("/search ") or text.startswith("/recall "):
                q = text.split(" ", 1)[1].strip()
                if q and q not in self.state.search_history:
                    self.state.search_history.append(q)

        result = self._facade.execute_command(text)

        if result.status == "error":
            for err in result.errors:
                log.add_error(err)
                self.state.conversation_entries.append({"entry_type": "error", "text": err})
        elif result.status == "pending":
            self._dispatch_pending(result.output)
        elif result.output:
            self._handle_result(result.output)
            self.state.conversation_entries.append({"entry_type": "result", "data": result.output})

    def _remember_target(self, target: str) -> None:
        if not target:
            return
        self.state.current_target = target
        recents = self.state.recent_targets
        if target in recents:
            recents.remove(target)
        recents.append(target)
        del recents[:-20]

    def _dispatch_pending(self, output: dict) -> None:
        rtype = output.get("type", "")
        target = output.get("target", "")
        if rtype == "recon":
            self._remember_target(target)
            self.run_worker(self._worker_recon(target, output.get("depth", 3)),
                            name=f"recon-{target}", thread=True)
        elif rtype == "scan":
            self._remember_target(target)
            self.run_worker(
                self._worker_scan(target, output.get("vuln_class", ""), output.get("context", "any")),
                name=f"scan-{target}", thread=True)
        elif rtype == "attack_campaign":
            self._remember_target(target)
            self.run_worker(self._worker_campaign(target, output.get("classes", "xss,sqli")),
                            name=f"campaign-{target}", thread=True)
        else:
            self.query_one("#conversation", ChatView).add_system(
                f"Pending: {rtype} (no worker available)")

    async def _worker_recon(self, target: str, depth: int):
        return self._services.scan.execute_recon(target, depth=depth)

    async def _worker_scan(self, target: str, vuln_class: str, context: str):
        return self._services.scan.execute_scan(target, vuln_class, context=context)

    async def _worker_campaign(self, target: str, classes: str):
        return self._services.scan.execute_campaign(target, classes)

    # ── Autonomous agent ──

    def _dispatch_agent(self, text: str) -> None:
        """Handle `/agent <objective>` — run the autonomous engine in a worker."""
        objective = text[len("/agent"):].strip()
        log = self.query_one("#conversation", ChatView)
        if not objective:
            log.add_system("Usage: /agent <objective>  —  e.g. /agent assess example.com")
            return
        self.run_worker(self._worker_agent(objective),
                        name=f"agent-{objective[:24]}", thread=True)

    async def _worker_agent(self, objective: str):
        return self._services.agent_engine.run(
            objective, self._agent_execute, facade=self._facade)

    def _agent_execute(self, command: str):
        """Command callable for the agent: runs via the facade, resolving the
        pending recon/scan/campaign dispatches exactly as the manual UI does.
        This adapter (not the agent Executor) is what touches ScanService."""
        result = self._facade.execute_command(command)
        if getattr(result, "status", None) != "pending":
            return result
        out = getattr(result, "output", {}) or {}
        rtype = out.get("type", "")
        target = out.get("target", "")
        try:
            if rtype == "recon":
                return self._services.scan.execute_recon(target, depth=out.get("depth", 3))
            if rtype == "scan":
                return self._services.scan.execute_scan(
                    target, out.get("vuln_class", ""), context=out.get("context", "any"))
            if rtype == "attack_campaign":
                return self._services.scan.execute_campaign(
                    target, out.get("classes", "xss,sqli"))
        except Exception as exc:
            return {"error": str(exc)}
        return {"status": "dispatched", **out}

    def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        if event.state == WorkerState.SUCCESS:
            result = event.worker.result
            if isinstance(result, dict) and result.get("error"):
                self.query_one("#conversation", ChatView).add_error(
                    f"Worker {event.worker.name}: {result['error']}")
            elif isinstance(result, dict):
                self._render_tool_result(event.worker.name, result)
        elif event.state == WorkerState.ERROR:
            self.query_one("#conversation", ChatView).add_error(
                f"Worker {event.worker.name} failed: {event.worker.error}")
            self._notify(f"Task failed: {event.worker.name}", "error")
        running = sum(1 for w in self.workers if w.state == WorkerState.RUNNING)
        self._services.monitor.set_worker_count(running)

    def _render_tool_result(self, name: str, result: dict) -> None:
        log = self.query_one("#conversation", ChatView)
        status = result.get("status", "")
        if status == "mcp_fallback":
            log.add_system(f"MCP tools available: {', '.join(result.get('tools', []))}")
            log.add_system(f"Run directly via MCP for {result.get('target', '?')}")
        elif "confirmed" in result:
            confirmed = result.get("confirmed", [])
            suspected = result.get("suspected", [])
            if confirmed:
                log.add_system(f"Confirmed findings: {len(confirmed)}")
                for f in confirmed[:5]:
                    log.add_result({"type": "finding_detail", "finding": f})
            if suspected:
                log.add_system(f"Suspected findings: {len(suspected)}")
        self.query_one("#inspector", Inspector).inspect_json(f"Result: {name}", result)

    def _handle_result(self, output: dict) -> None:
        log = self.query_one("#conversation", ChatView)
        rtype = output.get("type", "")
        if rtype == "finding_detail":
            log.add_result(output)
            self.query_one("#drawer", ContextDrawer).show_finding(output.get("finding", {}))
            self.state.context_drawer_open = True
        elif rtype == "coverage":
            log.add_result(output)
        elif rtype == "knowledge_home":
            log.add_system("Knowledge base — use /search <query> or /recall <query>")
        elif rtype == "wiki_page":
            log.add_result(output)
            page = output.get("page")
            if page:
                drawer = self.query_one("#drawer", ContextDrawer)
                drawer.show_wiki_page(page) if isinstance(page, dict) else drawer.show_text(
                    output.get("slug", "?"), str(page))
                self.state.context_drawer_open = True
                self.state.selected_wiki_page = output.get("slug", "?")
        else:
            log.add_result(output)

    # ── Event bridge handlers ──

    def on_tool_started(self, event: ToolStarted) -> None:
        self.state.active_tools.append(event.tool)
        log = self.query_one("#conversation", ChatView)
        log.add_system(f"Started: {event.tool}" + (f" → {event.target}" if event.target else ""))
        self.query_one("#tasks", TaskPanel).add_job(
            event.tool, f"{event.tool} {event.target}".strip())

    def on_tool_output_chunk(self, event: ToolOutputChunk) -> None:
        self.query_one("#conversation", ChatView).stream_chunk(event.chunk)

    def on_tool_completed(self, event: ToolCompleted) -> None:
        if event.tool in self.state.active_tools:
            self.state.active_tools.remove(event.tool)
        self.query_one("#conversation", ChatView).add_system(f"Completed: {event.tool}")
        self.query_one("#tasks", TaskPanel).finish_job(event.tool, "done")
        if event.tool in ("recon", "scan", "campaign"):
            self._notify(f"{event.tool.capitalize()} complete", "success")

    def on_tool_failed(self, event: ToolFailed) -> None:
        if event.tool in self.state.active_tools:
            self.state.active_tools.remove(event.tool)
        self.query_one("#conversation", ChatView).add_error(f"{event.tool} failed: {event.error}")
        self.query_one("#tasks", TaskPanel).finish_job(event.tool, "error")
        self._notify(f"Task failed: {event.tool}", "error")

    def on_ai_token(self, event: AIToken) -> None:
        self.query_one("#conversation", ChatView).stream_token(event.token)

    def on_finding_created(self, event: FindingCreated) -> None:
        self.query_one("#conversation", ChatView).add_system(
            f"New finding: {event.finding_id} [{event.severity}]")
        self._notify(f"Finding discovered: {event.finding_id} [{event.severity}]", "warning")

    def on_finding_transitioned(self, event: FindingTransitioned) -> None:
        self._notify(f"Finding {event.finding_id} → {event.to_state}", "information")

    def on_workflow_advanced(self, event: WorkflowAdvanced) -> None:
        self.state.current_workflow_id = event.run_id
        if event.state == "done":
            self._notify("Workflow finished", "success")

    def on_agent_spawned(self, event: AgentSpawned) -> None:
        self._notify(f"Agent spawned: {event.agent_type}", "information")

    def on_agent_task_completed(self, event: AgentTaskCompleted) -> None:
        self._notify(f"Agent {event.agent_type}: {event.status}", "information")

    # ── Autonomous agent event stream (rendered naturally in chat) ──

    def _chat(self) -> ChatView | None:
        """The conversation widget, or None if the UI is tearing down."""
        try:
            return self.query_one("#conversation", ChatView)
        except Exception:
            return None

    def on_agent_started(self, event: AgentStarted) -> None:
        chat = self._chat()
        if chat is not None:
            chat.write(mr.agent_started(event.objective, event.target))
        if event.target:
            self.state.current_target = event.target
        self._notify(f"Agent started: {event.objective[:40]}", "information")

    def on_agent_plan_ready(self, event: AgentPlanReady) -> None:
        chat = self._chat()
        session = self._agent_session(event.session_id)
        if chat is not None and session is not None:
            tasks = [t.to_dict() for t in session.plan.tasks]
            chat.write(mr.agent_plan_tree(tasks, session.target))

    def on_agent_reasoning(self, event: AgentReasoning) -> None:
        chat = self._chat()
        if chat is not None:
            chat.write(mr.agent_reasoning(event.phase, event.thought))

    def on_agent_task_update(self, event: AgentTaskUpdate) -> None:
        chat = self._chat()
        if chat is not None and event.state in ("completed", "failed"):
            chat.write(mr.agent_task_line(event.state, event.command, event.description))

    def on_agent_goal_progress(self, event: AgentGoalProgress) -> None:
        try:
            self.query_one("#drawer", ContextDrawer).show_agent(event.payload)
            self.state.context_drawer_open = True
        except Exception:
            pass

    def on_agent_run_finished(self, event: AgentRunFinished) -> None:
        snapshot = None
        session = self._agent_session(event.session_id)
        if session is not None:
            from hydra.agent.goals import GoalTracker
            snapshot = GoalTracker(session.plan).snapshot()
            snapshot["state"] = session.state.value
            snapshot["objective"] = session.objective
        chat = self._chat()
        if chat is not None:
            chat.write(mr.agent_finished(event.status, snapshot))
        self._notify(f"Agent {event.status}",
                     "success" if event.status == "completed" else "warning")

    def _agent_session(self, session_id: str):
        try:
            return self._services.agent_engine.get_session(session_id)
        except Exception:
            return None

    def on_hydra_event(self, event: HydraEvent) -> None:
        etype = event.event_type
        if etype.startswith("knowledge") or etype in ("lesson.recorded",):
            self._notify("Knowledge updated", "information")
        elif etype == "plugin.loaded":
            self._notify("Plugin loaded", "information")

    # ── Sidebar navigation ──

    def on_nav_selected(self, event: NavSelected) -> None:
        if event.section == "recent" or event.section == "pinned":
            data = self._services.session.load(event.value)
            if data:
                self.query_one("#conversation", ChatView).add_system(
                    f"Loaded session {event.value}")
        elif event.section == "reports":
            self.run_command(f"/wiki {event.value}")
        elif event.section == "graphs":
            self.run_command(f"/search {event.value}")
        elif event.section == "bookmarks":
            self.fill_prompt(event.value)

    def _refresh_sidebar(self) -> None:
        try:
            sidebar = self.query_one("#sidebar", SessionSidebar)
        except Exception:
            return
        data: dict[str, list[dict]] = {}
        try:
            sessions = self._services.session.list_sessions()
            data["recent"] = [
                {"label": s.get("target") or s.get("session_id", "?"),
                 "value": s.get("session_id", "")}
                for s in sessions[:20]
            ]
        except Exception:
            data["recent"] = []
        data["pinned"] = [{"label": s, "value": s} for s in self.state.pinned_sessions]
        data["bookmarks"] = [{"label": b, "value": b} for b in self.state.bookmarks]
        try:
            reports = self._facade.list_reports()
            data["reports"] = [
                {"label": r.get("title") or r.get("slug", "?"), "value": r.get("slug", "")}
                for r in (reports or [])[:30]
            ]
        except Exception:
            data["reports"] = []
        data["graphs"] = [{"label": t, "value": t} for t in self.state.recent_targets[-10:]]
        sidebar.populate(data)

    # ── 1s monitor refresh (the only timer) ──

    def _refresh_metrics(self) -> None:
        try:
            mem = self._services.monitor.get_memory()
            events = self._services.monitor.get_events()
        except Exception:
            mem, events = {}, {}
        try:
            load = os.getloadavg()[0] if hasattr(os, "getloadavg") else 0.0
        except OSError:
            load = 0.0
        running = sum(1 for w in self.workers if w.state == WorkerState.RUNNING)

        try:
            status = self.query_one("#status", StatusBar)
            status.workspace = self.state.current_workspace
            status.profile = self.state.current_profile
            status.memory_mb = mem.get("rss_mb", 0.0)
            status.cpu_load = load
            status.worker_count = running
            status.events_per_sec = events.get("throughput", 0.0)
            status.scope = self.state.current_target or ""
            status.connected = True
            self.query_one("#header", HeaderBar).connected = True
            tasks = self.query_one("#tasks", TaskPanel)
            if tasks.has_class("visible"):
                tasks.tick()
        except Exception:
            pass

    # ── Palette / theme helpers ──

    def fill_prompt(self, text: str) -> None:
        cmd_input = self.query_one("#input", CommandInput)
        cmd_input.text = text
        try:
            cmd_input.move_cursor(cmd_input.document.end)
        except Exception:
            pass
        cmd_input.focus()

    def apply_theme(self, name: str) -> None:
        try:
            self.theme = resolve_theme(name)
            self.state.theme = name
            self._notify(f"Theme: {name}", "information")
        except Exception:
            pass

    def command_history(self) -> list[str]:
        try:
            return self.query_one("#input", CommandInput).get_history()
        except Exception:
            return []

    def _notify(self, message: str, severity: str = "information") -> None:
        notify_sev = severity if severity in _NOTIFY_SEVERITIES else "information"
        try:
            self.notify(message, severity=notify_sev)
        except Exception:
            pass
        try:
            self.query_one("#notifications", NotificationCenter).add(message, severity)
        except Exception:
            pass

    # ── Actions ──

    def action_cancel_task(self) -> None:
        cancelled = 0
        for worker in list(self.workers):
            if worker.state == WorkerState.RUNNING:
                worker.cancel()
                cancelled += 1
        if cancelled:
            self._notify(f"Cancelled {cancelled} task(s)", "warning")
        else:
            self.query_one("#conversation", ChatView).add_system("No running tasks to cancel.")

    def action_clear_log(self) -> None:
        self.query_one("#conversation", ChatView).clear()
        self.state.conversation_entries.clear()

    def action_new_session(self) -> None:
        if self.state.session_id:
            self._services.session.save(self.state.session_id, self.state.to_dict())
        self.state = WorkspaceState()
        self.state.session_id = f"session-{uuid.uuid4().hex[:8]}"
        self.state.theme = self.theme
        self.query_one("#conversation", ChatView).clear()
        self._notify("New session", "information")

    def action_toggle_sidebar(self) -> None:
        sidebar = self.query_one("#sidebar", SessionSidebar)
        visible = not sidebar.has_class("visible")
        sidebar.set_class(visible, "visible")
        self.state.sidebar_visible = visible
        if visible:
            self._refresh_sidebar()

    def action_toggle_tasks(self) -> None:
        tasks = self.query_one("#tasks", TaskPanel)
        visible = not tasks.has_class("visible")
        tasks.set_class(visible, "visible")
        self.state.task_panel_open = visible

    def action_toggle_notifications(self) -> None:
        nc = self.query_one("#notifications", NotificationCenter)
        visible = not nc.has_class("visible")
        nc.set_class(visible, "visible")
        self.state.notification_open = visible

    def action_cycle_theme(self) -> None:
        try:
            idx = HYDRA_THEMES.index(self.state.theme)
        except ValueError:
            idx = -1
        self.apply_theme(HYDRA_THEMES[(idx + 1) % len(HYDRA_THEMES)])

    def action_close_overlays(self) -> None:
        self.query_one("#inspector", Inspector).close()
        self.query_one("#drawer", ContextDrawer).close()
        self.query_one("#notifications", NotificationCenter).remove_class("visible")
        self.state.context_drawer_open = False
        self.state.notification_open = False
        self.query_one("#input", CommandInput).focus()
