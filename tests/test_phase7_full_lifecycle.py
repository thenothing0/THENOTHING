"""Phase 7 full lifecycle test — plugin integration, AI session, end-to-end.

Validates:
1. Sample plugin registers command + capability
2. /ping executes through plugin → TUI pipeline
3. AI session chat fallthrough works
4. Event bridge handles AI events
5. Full lifecycle: startup → commands → tool events → findings → workflow → knowledge
6. All 24+ commands are discovered via PresentationAPI
7. WorkspaceState tracks everything
"""

import asyncio
import sys
import os

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from hydra.services.event_bus import EventBus
from hydra.services import ServiceContainer
from hydra.commands.registry import CommandRegistry
from hydra.commands.builtins import register_all_builtins
from hydra.facade import HydraFacade
from hydra.presentation.api import PresentationAPI
from hydra.registry.capability import CapabilityRegistry, CapabilityType


def make_stack():
    bus = EventBus()
    reg = CapabilityRegistry()
    svc = ServiceContainer(event_bus=bus)
    cmd = CommandRegistry()
    register_all_builtins(cmd, reg)
    facade = HydraFacade(svc, reg, bus, cmd)
    api = PresentationAPI(facade, reg, bus)
    return facade, svc, bus, cmd, reg, api


# ── Plugin integration ──

def test_plugin_registration():
    facade, svc, bus, cmd, reg, api = make_stack()

    from hydra.plugins.sample_plugin import SamplePlugin
    plugin = SamplePlugin()
    asyncio.run(plugin.initialize({}))
    plugin.register_commands(cmd, reg)

    assert cmd.get("ping") is not None
    assert reg.get("ping") is not None
    plugin_cap = reg.get(f"plugin:{plugin.NAME}")
    assert plugin_cap is not None
    assert plugin_cap.type == CapabilityType.PLUGIN
    print("  [PASS] Sample plugin registered command + capability")


def test_plugin_execution():
    facade, svc, bus, cmd, reg, api = make_stack()

    from hydra.plugins.sample_plugin import SamplePlugin
    plugin = SamplePlugin()
    asyncio.run(plugin.initialize({}))
    plugin.register_commands(cmd, reg)

    result = facade.execute_command("/ping")
    assert result.ok
    assert result.output["type"] == "plugin_result"
    assert result.output["result"]["status"] == "pong"
    print("  [PASS] /ping executes through plugin pipeline")


def test_plugin_discovered():
    facade, svc, bus, cmd, reg, api = make_stack()

    from hydra.plugins.sample_plugin import SamplePlugin
    plugin = SamplePlugin()
    asyncio.run(plugin.initialize({}))
    plugin.register_commands(cmd, reg)

    cmds = api.list_commands()
    names = [c.name for c in cmds]
    assert "ping" in names
    print(f"  [PASS] Plugin command discovered via PresentationAPI ({len(cmds)} total)")


# ── AI session ──

def test_chat_fallthrough():
    facade, svc, bus, cmd, reg, api = make_stack()

    events = []
    bus.subscribe("ai.*", lambda e: events.append(e))

    result = facade.execute_command("Hello, how are you?")
    assert result.ok
    assert result.output["type"] == "chat"
    assert len(result.output["message"]) > 0

    event_types = [e.type for e in events]
    assert "ai.chat_started" in event_types
    print(f"  [PASS] Chat fallthrough works (response: {result.output['message'][:40]}...)")


def test_ai_session_info():
    facade, _, _, _, _, _ = make_stack()
    session = facade.get_ai_session()
    info = session.get_info()
    assert "provider" in info
    assert "messages" in info
    assert "context_used" in info
    print(f"  [PASS] AI session info: {info}")


def test_ai_session_history():
    facade, _, _, _, _, _ = make_stack()
    session = facade.get_ai_session()
    session.send("test message", stream=False)
    history = session.get_history()
    assert len(history) >= 2  # user + assistant
    assert history[0]["role"] == "user"
    print(f"  [PASS] AI session tracks history ({len(history)} messages)")


# ── Event bridge AI events ──

def test_event_bridge_ai():
    pytest.importorskip("textual")
    from control_center.tui.event_bridge import EventBridge, AIToken, AIChatCompleted
    from unittest.mock import MagicMock

    app = MagicMock()
    bus = EventBus()
    bridge = EventBridge(app, bus)
    bridge.connect()

    bus.emit("ai.token", {"token": "Hello"})
    bus.emit("ai.chat_completed", {"length": 42})

    posted = [call.args[0] for call in app.post_message.call_args_list]
    tokens = [m for m in posted if isinstance(m, AIToken)]
    completions = [m for m in posted if isinstance(m, AIChatCompleted)]
    assert len(tokens) == 1 and tokens[0].token == "Hello"
    assert len(completions) == 1 and completions[0].length == 42
    bridge.disconnect()
    print("  [PASS] EventBridge handles AI token + completion events")


# ── Full lifecycle ──

def test_full_lifecycle():
    facade, svc, bus, cmd, reg, api = make_stack()

    events = []
    bus.subscribe("*", lambda e: events.append(e))

    # 1. System status
    r = facade.execute_command("/status")
    assert r.ok and r.output["type"] == "status"

    # 2. Help
    r = facade.execute_command("/help")
    assert r.ok and r.output["type"] == "help"
    assert len(r.output["commands"]) >= 24

    # 3. Tools check
    r = facade.execute_command("/tools")
    assert r.ok and r.output["type"] == "tools"

    # 4. Scope
    r = facade.execute_command("/scope register acme --platform=hackerone --in_scope=*.acme.com")
    assert r.ok and r.output["type"] == "scope_register"

    # 5. Recon (returns pending)
    r = facade.execute_command("/recon acme.com")
    assert r.status == "pending" and r.output["type"] == "recon"

    # 6. Execute recon directly (as worker would)
    recon_result = svc.scan.execute_recon("acme.com")
    assert isinstance(recon_result, dict)

    # 7. Scan (returns pending)
    r = facade.execute_command("/scan acme.com xss")
    assert r.status == "pending"

    # 8. Search knowledge
    r = facade.execute_command("/search waf bypass")
    assert r.ok and r.output["type"] == "search_results"

    # 9. Recall
    r = facade.execute_command("/recall idor")
    assert r.ok and r.output["type"] == "recall_results"

    # 10. Coverage
    r = facade.execute_command("/coverage")
    assert r.ok

    # 11. Findings
    r = facade.execute_command("/findings")
    assert r.ok

    # 12. Workflow
    r = facade.execute_command("/workflow")
    assert r.ok

    # 13. Engage
    r = facade.execute_command("/engage")
    assert r.ok

    # 14. Chat
    r = facade.execute_command("what vulnerabilities should I look for?")
    assert r.ok and r.output["type"] == "chat"

    # 15. Clear
    r = facade.execute_command("/clear")
    assert r.ok

    # 16. Next targets
    r = facade.execute_command("/next")
    assert r.ok

    # 17. Lint
    r = facade.execute_command("/lint")
    assert r.ok

    # 18. Learn
    r = facade.execute_command("/learn always check CORS headers --tier=project")
    assert r.ok

    print(f"  [PASS] Full lifecycle: 18 operations, {len(events)} events emitted")


def test_workspace_state():
    from control_center.tui.state import WorkspaceState

    state = WorkspaceState()
    assert state.current_engagement_id is None
    assert state.current_target is None
    assert state.sidebar_visible is True
    assert state.bottom_panel_open is False
    assert state.context_drawer_open is False
    assert state.active_tools == []

    state.current_target = "test.com"
    state.active_tools.append("recon")
    state.bottom_panel_open = True

    assert state.current_target == "test.com"
    assert len(state.active_tools) == 1
    assert state.bottom_panel_open is True
    print("  [PASS] WorkspaceState tracks all fields correctly")


def test_conversation_plugin_renderer():
    pytest.importorskip("textual")
    from control_center.tui.widgets.conversation import ConversationLog
    from unittest.mock import MagicMock

    log = ConversationLog()
    log.write = MagicMock()

    log.add_result({
        "type": "plugin_result",
        "plugin": "sample_plugin",
        "result": {"status": "pong", "message": "Sample plugin is alive"},
    })
    assert log.write.called
    print("  [PASS] Conversation log renders plugin_result type")


def test_command_completeness():
    facade, svc, bus, cmd, reg, api = make_stack()

    cmds = api.list_commands()
    names = sorted(c.name for c in cmds)

    required = sorted([
        "help", "status", "clear", "tools", "session",
        "findings", "coverage", "knowledge", "workflow", "engage",
        "recon", "scan", "scope", "attack",
        "finding", "validate", "confirm", "reject",
        "search", "recall", "learn", "wiki", "next", "lint",
    ])

    missing = [n for n in required if n not in names]
    assert not missing, f"Missing commands: {missing}"
    print(f"  [PASS] All {len(required)} required commands present (total: {len(names)})")
    print(f"         Commands: {', '.join(names)}")


if __name__ == "__main__":
    print("\n=== Phase 7: Full Lifecycle Integration Tests ===\n")
    test_plugin_registration()
    test_plugin_execution()
    test_plugin_discovered()
    test_chat_fallthrough()
    test_ai_session_info()
    test_ai_session_history()
    test_event_bridge_ai()
    test_full_lifecycle()
    test_workspace_state()
    test_conversation_plugin_renderer()
    test_command_completeness()
    print("\n=== ALL PHASE 7 TESTS PASSED ===\n")
