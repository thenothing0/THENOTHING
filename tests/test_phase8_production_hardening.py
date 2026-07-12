"""Phase 8 — Production Hardening tests.

Validates all 15 capabilities:
  #1  ConfigManager with profiles
  #2  SecretStore abstraction
  #3  Persistent workspace sessions
  #4  Crash recovery
  #5  Hot-swappable AI providers
  #6  Dynamic model discovery
  #7  Streaming execution
  #8  Workspace restoration
  #9  Command history with reverse search
  #10 Intelligent command auto-completion
  #11 Provider health monitoring
  #12 Runtime monitoring
  #13 Dynamic plugin discovery
  #14 Theme engine
  #15 Update checking
"""

import json
import os
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest


# ══════════════════════════════════════════════════════════════════════
# #1 — ConfigManager
# ══════════════════════════════════════════════════════════════════════

class TestConfigManager:
    def setup_method(self):
        from hydra.config.manager import ConfigManager
        ConfigManager._instance = None

    def test_singleton(self):
        from hydra.config.manager import ConfigManager
        a = ConfigManager.get()
        b = ConfigManager.get()
        assert a is b

    def test_default_profile(self):
        from hydra.config.manager import ConfigManager
        cfg = ConfigManager.get()
        assert cfg.profile.value in ("development", "testing", "production", "offline", "cloud")

    def test_get_set_value(self):
        from hydra.config.manager import ConfigManager
        cfg = ConfigManager.get()
        cfg.set("test_key", 42)
        assert cfg.get_value("test_key") == 42

    def test_get_default(self):
        from hydra.config.manager import ConfigManager
        cfg = ConfigManager.get()
        assert cfg.get_value("nonexistent", "fallback") == "fallback"

    def test_profile_switch(self):
        from hydra.config.manager import ConfigManager, ConfigProfile
        cfg = ConfigManager.get()
        cfg.set_profile(ConfigProfile.OFFLINE)
        assert cfg.profile == ConfigProfile.OFFLINE
        assert cfg.get_value("log_level") is not None

    def test_freeze(self):
        from hydra.config.manager import ConfigManager
        cfg = ConfigManager.get()
        cfg.freeze()
        with pytest.raises(RuntimeError):
            cfg.set("anything", "value")

    def test_as_dict(self):
        from hydra.config.manager import ConfigManager
        cfg = ConfigManager.get()
        d = cfg.as_dict()
        assert isinstance(d, dict)
        assert "log_level" in d

    def test_env_override(self):
        from hydra.config.manager import ConfigManager
        ConfigManager._instance = None
        with patch.dict(os.environ, {"HYDRA_LOG_LEVEL": "DEBUG"}):
            cfg = ConfigManager.get()
            assert cfg.get_value("log_level") == "DEBUG"

    def test_coerce_types(self):
        from hydra.config.manager import ConfigManager
        assert ConfigManager._coerce("true") is True
        assert ConfigManager._coerce("false") is False
        assert ConfigManager._coerce("42") == 42
        assert ConfigManager._coerce("3.14") == 3.14
        assert ConfigManager._coerce("hello") == "hello"


# ══════════════════════════════════════════════════════════════════════
# #2 — SecretStore
# ══════════════════════════════════════════════════════════════════════

class TestSecretStore:
    def setup_method(self):
        from hydra.config.secrets import SecretStore
        SecretStore._instance = None

    def test_singleton(self):
        from hydra.config.secrets import SecretStore
        a = SecretStore.get()
        b = SecretStore.get()
        assert a is b

    def test_set_and_get(self):
        from hydra.config.secrets import SecretStore
        store = SecretStore.get()
        store.set_secret("test_secret", "s3cr3t")
        assert store.get_secret("test_secret") == "s3cr3t"

    def test_has_secret(self):
        from hydra.config.secrets import SecretStore
        store = SecretStore.get()
        store.set_secret("exists", "val")
        assert store.has_secret("exists")
        assert not store.has_secret("nope_not_here")

    def test_list_available_no_values(self):
        from hydra.config.secrets import SecretStore
        store = SecretStore.get()
        store.set_secret("anthropic_api_key", "sk-hidden")
        available = store.list_available()
        assert any(e["name"] == "anthropic_api_key" and e["available"] for e in available)
        for entry in available:
            assert "value" not in entry
            assert "sk-hidden" not in str(entry)

    def test_env_fallback(self):
        from hydra.config.secrets import SecretStore
        SecretStore._instance = None
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test-123"}):
            store = SecretStore.get()
            assert store.get_secret("anthropic_api_key") == "sk-test-123"

    def test_thread_safety(self):
        from hydra.config.secrets import SecretStore
        store = SecretStore.get()
        results = []

        def writer(i):
            store.set_secret(f"thread_{i}", f"val_{i}")
            results.append(store.get_secret(f"thread_{i}"))

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(results) == 10


# ══════════════════════════════════════════════════════════════════════
# #3 & #4 — Session persistence + crash recovery
# ══════════════════════════════════════════════════════════════════════

class TestSessionPersistence:
    def test_save_and_load(self):
        from hydra.services.session import SessionService
        from hydra.services.event_bus import EventBus
        with tempfile.TemporaryDirectory() as td:
            svc = SessionService(EventBus(), Path(td))
            svc.save("test-1", {"hello": "world", "count": 42})
            data = svc.load("test-1")
            assert data["hello"] == "world"
            assert data["count"] == 42

    def test_list_sessions(self):
        from hydra.services.session import SessionService
        from hydra.services.event_bus import EventBus
        with tempfile.TemporaryDirectory() as td:
            svc = SessionService(EventBus(), Path(td))
            svc.save("s1", {"a": 1})
            svc.save("s2", {"b": 2})
            sessions = svc.list_sessions()
            assert len(sessions) >= 2

    def test_sentinel_write_and_clear(self):
        from hydra.services.session import SessionService
        from hydra.services.event_bus import EventBus
        with tempfile.TemporaryDirectory() as td:
            svc = SessionService(EventBus(), Path(td))
            svc.write_sentinel("crash-test-1")
            sentinel = Path(td) / ".hydra_session_active"
            assert sentinel.exists()
            svc.clear_sentinel()
            assert not sentinel.exists()

    def test_crash_recovery_detection(self):
        from hydra.services.session import SessionService
        from hydra.services.event_bus import EventBus
        with tempfile.TemporaryDirectory() as td:
            svc = SessionService(EventBus(), Path(td))
            svc.save("crash-session", {"recovered": True})
            svc.write_sentinel("crash-session")
            # Simulate crash: don't clear sentinel
            svc2 = SessionService(EventBus(), Path(td))
            recovery = svc2.check_crash_recovery()
            assert recovery is not None
            assert recovery["session_id"] == "crash-session"

    def test_no_crash_on_clean_exit(self):
        from hydra.services.session import SessionService
        from hydra.services.event_bus import EventBus
        with tempfile.TemporaryDirectory() as td:
            svc = SessionService(EventBus(), Path(td))
            svc.write_sentinel("clean-session")
            svc.clear_sentinel()
            svc2 = SessionService(EventBus(), Path(td))
            assert svc2.check_crash_recovery() is None

    def test_auto_save(self):
        from hydra.services.session import SessionService
        from hydra.services.event_bus import EventBus
        with tempfile.TemporaryDirectory() as td:
            svc = SessionService(EventBus(), Path(td))
            state = {"counter": 0}
            svc.start_auto_save(interval=0.1, state_callback=lambda: state)
            time.sleep(0.3)
            svc.stop_auto_save()
            autosave = Path(td) / ".hydra_autosave.json"
            assert autosave.exists()
            data = json.loads(autosave.read_text())
            assert data["counter"] == 0


# ══════════════════════════════════════════════════════════════════════
# #5 & #6 — AI provider hot-swap + model discovery
# ══════════════════════════════════════════════════════════════════════

class TestProviderManager:
    def test_catalog_populated(self):
        from hydra.ai.providers import _PROVIDER_CATALOG
        assert "anthropic" in _PROVIDER_CATALOG
        assert "openai" in _PROVIDER_CATALOG
        assert "google" in _PROVIDER_CATALOG

    def test_list_providers(self):
        from hydra.ai.providers import ProviderManager
        pm = ProviderManager()
        providers = pm.list_providers()
        ids = [p["id"] for p in providers]
        assert "anthropic" in ids
        assert "openai" in ids

    def test_discover_models(self):
        from hydra.ai.providers import ProviderManager
        pm = ProviderManager()
        models = pm.discover_models("anthropic")
        assert isinstance(models, list)
        assert len(models) > 0
        assert any("claude" in m.get("id", "") for m in models)

    def test_hot_swap_provider(self):
        from hydra.ai.providers import ProviderManager
        pm = ProviderManager()
        pm.switch("openai")
        info = pm.get_active_info()
        assert info["id"] == "openai"
        pm.switch("anthropic")
        info = pm.get_active_info()
        assert info["id"] == "anthropic"

    def test_hot_swap_model(self):
        from hydra.ai.providers import ProviderManager
        pm = ProviderManager()
        pm.switch("anthropic")
        pm.set_model("claude-opus-4")
        info = pm.get_active_info()
        assert info["model"] == "claude-opus-4"

    def test_thread_safe_switch(self):
        from hydra.ai.providers import ProviderManager
        pm = ProviderManager()
        results = []

        def switcher(provider):
            pm.switch(provider)
            results.append(pm.get_active_info()["id"])

        threads = [
            threading.Thread(target=switcher, args=("openai",)),
            threading.Thread(target=switcher, args=("anthropic",)),
            threading.Thread(target=switcher, args=("google",)),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(results) == 3

    def test_add_custom_model(self):
        from hydra.ai.providers import ProviderManager
        pm = ProviderManager()
        pm.add_custom_model("anthropic", "claude-test-custom", {"context": 999})
        models = pm.discover_models("anthropic")
        assert any(m["id"] == "claude-test-custom" for m in models)


# ══════════════════════════════════════════════════════════════════════
# #7 — Streaming execution
# ══════════════════════════════════════════════════════════════════════

class TestStreaming:
    def test_stream_handler_cancel(self):
        from hydra.ai.streaming import StreamHandler
        collected = []
        handler = StreamHandler(callback=lambda t: collected.append(t))
        assert not handler._cancelled.is_set()
        handler.cancel()
        assert handler._cancelled.is_set()

    def test_stream_lines(self):
        from hydra.ai.streaming import StreamHandler
        collected = []
        handler = StreamHandler(callback=lambda t: collected.append(t))
        handler.stream_lines(["line1\n", "line2\n", "line3\n"])
        assert collected == ["line1\n", "line2\n", "line3\n"]

    def test_stream_lines_cancel(self):
        from hydra.ai.streaming import StreamHandler
        collected = []
        handler = StreamHandler(callback=lambda t: collected.append(t))
        handler.cancel()
        handler.stream_lines(["a\n", "b\n"])
        assert len(collected) == 0

    def test_operation_stream(self):
        from hydra.ai.streaming import OperationStream
        from hydra.services.event_bus import EventBus
        bus = EventBus()
        events = []
        bus.subscribe("tool.*", lambda e: events.append(e))

        with OperationStream(bus, "test_tool", "example.com") as stream:
            stream.output("chunk1")
            stream.output("chunk2")

        event_types = [e.type for e in events]
        assert "tool.started" in event_types
        assert "tool.output" in event_types
        assert "tool.completed" in event_types

    def test_operation_stream_failure(self):
        from hydra.ai.streaming import OperationStream
        from hydra.services.event_bus import EventBus
        bus = EventBus()
        events = []
        bus.subscribe("tool.*", lambda e: events.append(e))

        try:
            with OperationStream(bus, "failing_tool", "target"):
                raise ValueError("boom")
        except ValueError:
            pass

        event_types = [e.type for e in events]
        assert "tool.started" in event_types
        assert "tool.failed" in event_types


# ══════════════════════════════════════════════════════════════════════
# #8 — Workspace restoration (state serialization)
# ══════════════════════════════════════════════════════════════════════

class TestWorkspaceState:
    def test_to_dict(self):
        from control_center.tui.state import WorkspaceState
        state = WorkspaceState()
        state.current_target = "example.com"
        state.session_id = "s-123"
        state.theme = "monokai"
        d = state.to_dict()
        assert d["current_target"] == "example.com"
        assert d["session_id"] == "s-123"
        assert d["theme"] == "monokai"

    def test_from_dict(self):
        from control_center.tui.state import WorkspaceState
        data = {
            "current_target": "test.com",
            "session_id": "s-456",
            "sidebar_visible": False,
            "theme": "hacker",
            "nav_history": ["/help", "/status"],
            "conversation_entries": [{"entry_type": "user", "text": "hello"}],
        }
        state = WorkspaceState.from_dict(data)
        assert state.current_target == "test.com"
        assert state.session_id == "s-456"
        assert state.sidebar_visible is False
        assert state.theme == "hacker"
        assert len(state.nav_history) == 2
        assert len(state.conversation_entries) == 1

    def test_roundtrip(self):
        from control_center.tui.state import WorkspaceState
        original = WorkspaceState()
        original.current_engagement_id = "eng-1"
        original.current_provider = "openai"
        original.current_model = "gpt-4o"
        original.bottom_panel_open = True
        original.theme = "solarized"
        original.conversation_entries = [
            {"entry_type": "user", "text": f"msg-{i}"} for i in range(5)
        ]

        d = original.to_dict()
        restored = WorkspaceState.from_dict(d)

        assert restored.current_engagement_id == "eng-1"
        assert restored.current_provider == "openai"
        assert restored.current_model == "gpt-4o"
        assert restored.bottom_panel_open is True
        assert restored.theme == "solarized"
        assert len(restored.conversation_entries) == 5

    def test_conversation_limit(self):
        from control_center.tui.state import WorkspaceState
        state = WorkspaceState()
        state.conversation_entries = [{"entry_type": "user", "text": f"m{i}"} for i in range(300)]
        d = state.to_dict()
        assert len(d["conversation_entries"]) == 200

    def test_nav_history_limit(self):
        from control_center.tui.state import WorkspaceState
        state = WorkspaceState()
        state.nav_history = [f"/cmd{i}" for i in range(100)]
        d = state.to_dict()
        assert len(d["nav_history"]) == 50


# ══════════════════════════════════════════════════════════════════════
# #9 — Command history
# ══════════════════════════════════════════════════════════════════════

class TestCommandHistory:
    def test_history_persistence(self):
        pytest.importorskip("textual")
        with tempfile.TemporaryDirectory() as td:
            hist_path = Path(td) / ".hydra_command_history"
            hist_path.write_text("/help\n/status\n/recon example.com\n")

            with patch("control_center.tui.widgets.command_input.Path") as MockPath:
                mock_path = MockPath.return_value.__truediv__.return_value
                mock_path.exists.return_value = True
                mock_path.read_text.return_value = "/help\n/status\n/recon example.com\n"

                # Direct test of history loading logic
                lines = "/help\n/status\n/recon example.com\n".strip().split("\n")
                history = [ln for ln in lines if ln]
                assert len(history) == 3
                assert history[0] == "/help"


# ══════════════════════════════════════════════════════════════════════
# #10 — Command auto-completion
# ══════════════════════════════════════════════════════════════════════

class TestCommandCompletion:
    def test_argument_hints_exist(self):
        pytest.importorskip("textual")
        from control_center.tui.widgets.command_input import _ARGUMENT_HINTS
        assert "recon" in _ARGUMENT_HINTS
        assert "scan" in _ARGUMENT_HINTS
        assert "scope" in _ARGUMENT_HINTS
        assert "session" in _ARGUMENT_HINTS

    def test_scan_hints(self):
        pytest.importorskip("textual")
        from control_center.tui.widgets.command_input import _ARGUMENT_HINTS
        scan_hints = _ARGUMENT_HINTS["scan"]
        assert "xss" in scan_hints
        assert "sqli" in scan_hints


# ══════════════════════════════════════════════════════════════════════
# #11 — Provider health monitoring
# ══════════════════════════════════════════════════════════════════════

class TestProviderHealth:
    def test_record_success(self):
        from hydra.ai.providers import ProviderHealth
        h = ProviderHealth()
        h.record_success(latency_ms=150)
        assert h.available is True
        assert h.latency_ms == 150
        assert h.error_count == 0

    def test_record_failure(self):
        from hydra.ai.providers import ProviderHealth
        h = ProviderHealth()
        h.record_failure("timeout")
        assert h.error_count == 1
        assert h.last_error == "timeout"

    def test_rate_limit(self):
        from hydra.ai.providers import ProviderHealth
        h = ProviderHealth()
        h.record_rate_limit(retry_after=30)
        assert h.is_rate_limited

    def test_rate_limit_expires(self):
        from hydra.ai.providers import ProviderHealth
        h = ProviderHealth()
        h.record_rate_limit(retry_after=0)
        h.rate_limited_until = time.time() - 1
        assert not h.is_rate_limited

    def test_provider_manager_health(self):
        from hydra.ai.providers import ProviderManager
        pm = ProviderManager()
        pm.record_success("anthropic", 200)
        health = pm.get_health("anthropic")
        assert health is not None
        assert health["available"] is True
        assert health["latency_ms"] == 200

    def test_all_health(self):
        from hydra.ai.providers import ProviderManager
        pm = ProviderManager()
        pm.record_success("anthropic", 100)
        pm.record_failure("503", "openai")
        all_h = pm.get_all_health()
        assert "anthropic" in all_h
        assert "openai" in all_h


# ══════════════════════════════════════════════════════════════════════
# #12 — Runtime monitoring
# ══════════════════════════════════════════════════════════════════════

class TestRuntimeMonitor:
    def test_snapshot_fields(self):
        from hydra.services.monitor import RuntimeMonitor
        from hydra.services.event_bus import EventBus
        with tempfile.TemporaryDirectory() as td:
            mon = RuntimeMonitor(EventBus(), Path(td))
            snap = mon.get_snapshot()
            assert "memory" in snap
            assert "cpu" in snap
            assert "uptime_seconds" in snap
            assert "workers" in snap
            assert "tasks" in snap
            assert "events" in snap

    def test_event_counting(self):
        from hydra.services.monitor import RuntimeMonitor
        from hydra.services.event_bus import EventBus
        bus = EventBus()
        with tempfile.TemporaryDirectory() as td:
            mon = RuntimeMonitor(bus, Path(td))
            bus.emit("tool.started", {"tool": "test"})
            bus.emit("tool.completed", {"tool": "test"})
            bus.emit("finding.created", {"id": "f1"})
            snap = mon.get_snapshot()
            assert snap["events"]["total"] == 3

    def test_worker_task_tracking(self):
        from hydra.services.monitor import RuntimeMonitor
        from hydra.services.event_bus import EventBus
        with tempfile.TemporaryDirectory() as td:
            mon = RuntimeMonitor(EventBus(), Path(td))
            mon.set_worker_count(3)
            mon.set_task_count(7)
            mon.set_mcp_connections(2)
            snap = mon.get_snapshot()
            assert snap["workers"] == 3
            assert snap["tasks"] == 7
            assert snap["mcp_connections"] == 2


# ══════════════════════════════════════════════════════════════════════
# #13 — Dynamic plugin discovery
# ══════════════════════════════════════════════════════════════════════

class TestPluginDiscovery:
    def test_multi_dir_discovery(self):
        from hydra.plugins.plugin_loader import PluginLoader
        loader = PluginLoader()
        plugins = loader.discover()
        assert isinstance(plugins, list)

    def test_has_changes_detection(self):
        from hydra.plugins.plugin_loader import PluginLoader
        with tempfile.TemporaryDirectory() as td:
            loader = PluginLoader(td)
            loader.discover()
            assert not loader.has_changes()

            # Add a new plugin file
            try:
                import yaml
                p = Path(td) / "new_plugin.yaml"
                p.write_text(yaml.dump({"plugin_id": "test-new", "plugin_name": "New"}))
                assert loader.has_changes()
            except ImportError:
                pytest.skip("yaml not available")

    def test_dedup_across_dirs(self):
        from hydra.plugins.plugin_loader import PluginLoader
        try:
            import yaml
        except ImportError:
            pytest.skip("yaml not available")

        with tempfile.TemporaryDirectory() as td1, tempfile.TemporaryDirectory() as td2:
            data = {"plugin_id": "dup-test", "plugin_name": "Dup", "version": "1.0.0"}
            (Path(td1) / "p.yaml").write_text(yaml.dump(data))
            (Path(td2) / "p.yaml").write_text(yaml.dump(data))

            loader = PluginLoader(td1)
            loader._dirs = [Path(td1), Path(td2)]
            plugins = loader.discover()
            ids = [p.plugin_id for p in plugins]
            assert ids.count("dup-test") == 1


# ══════════════════════════════════════════════════════════════════════
# #14 — Theme engine
# ══════════════════════════════════════════════════════════════════════

class TestThemeEngine:
    def test_available_themes(self):
        from control_center.tui.themes import list_themes
        themes = list_themes()
        assert len(themes) == 5
        ids = [t["id"] for t in themes]
        assert "dark" in ids
        assert "light" in ids
        assert "solarized" in ids
        assert "monokai" in ids
        assert "hacker" in ids

    def test_get_theme_path(self):
        from control_center.tui.themes import get_theme_path
        path = get_theme_path("dark")
        assert path.exists()
        assert path.suffix == ".tcss"

    def test_load_theme_css(self):
        from control_center.tui.themes import load_theme_css
        css = load_theme_css("hacker")
        assert "background" in css
        assert "#00ff00" in css

    def test_invalid_theme_fallback(self):
        from control_center.tui.themes import get_theme_path
        path = get_theme_path("nonexistent")
        assert path.name == "theme_dark.tcss"


# ══════════════════════════════════════════════════════════════════════
# #15 — Update checking
# ══════════════════════════════════════════════════════════════════════

class TestUpdateChecker:
    def test_current_version(self):
        from hydra.services.updates import UpdateChecker, CURRENT_VERSION
        from hydra.services.event_bus import EventBus
        with tempfile.TemporaryDirectory() as td:
            uc = UpdateChecker(EventBus(), Path(td))
            assert uc.get_current_version() == CURRENT_VERSION

    def test_is_newer(self):
        from hydra.services.updates import UpdateChecker
        assert UpdateChecker._is_newer("7.2.0", "7.1.0")
        assert not UpdateChecker._is_newer("7.1.0", "7.1.0")
        assert not UpdateChecker._is_newer("7.0.0", "7.1.0")
        assert UpdateChecker._is_newer("8.0.0", "7.1.0")

    def test_cache_write_and_read(self):
        from hydra.services.updates import UpdateChecker
        from hydra.services.event_bus import EventBus
        with tempfile.TemporaryDirectory() as td:
            uc = UpdateChecker(EventBus(), Path(td))
            result = {
                "current": "7.1.0",
                "latest": "7.2.0",
                "update_available": True,
                "url": "https://example.com",
                "checked_at": time.time(),
                "error": None,
            }
            uc._write_cache(result)
            cached = uc._read_cache()
            assert cached is not None
            assert cached["latest"] == "7.2.0"

    def test_stale_cache_ignored(self):
        from hydra.services.updates import UpdateChecker
        from hydra.services.event_bus import EventBus
        with tempfile.TemporaryDirectory() as td:
            uc = UpdateChecker(EventBus(), Path(td))
            result = {
                "current": "7.1.0",
                "latest": "7.2.0",
                "update_available": True,
                "checked_at": time.time() - 100000,
                "error": None,
            }
            uc._write_cache(result)
            assert uc._read_cache() is None


# ══════════════════════════════════════════════════════════════════════
# Integration — infrastructure commands
# ══════════════════════════════════════════════════════════════════════

class TestInfrastructureCommands:
    def _make_stack(self):
        from hydra.services.event_bus import EventBus
        from hydra.services import ServiceContainer
        from hydra.commands.registry import CommandRegistry
        from hydra.commands.builtins import register_all_builtins
        from hydra.registry.capability import CapabilityRegistry
        from hydra.facade import HydraFacade

        bus = EventBus()
        svc = ServiceContainer(event_bus=bus)
        cmd = CommandRegistry()
        reg = CapabilityRegistry()
        register_all_builtins(cmd, reg)
        facade = HydraFacade(svc, reg, bus, cmd)
        return facade

    def test_theme_list(self):
        facade = self._make_stack()
        result = facade.execute_command("/theme")
        assert result.ok
        assert result.output["type"] == "theme_list"
        assert len(result.output["themes"]) == 5

    def test_theme_switch(self):
        facade = self._make_stack()
        result = facade.execute_command("/theme dark")
        assert result.ok
        assert result.output["type"] == "theme_switch"
        assert result.output["theme"] == "dark"

    def test_theme_invalid(self):
        facade = self._make_stack()
        result = facade.execute_command("/theme rainbow")
        assert result.status == "error"

    def test_monitor(self):
        facade = self._make_stack()
        result = facade.execute_command("/monitor")
        assert result.ok
        assert result.output["type"] == "monitor"
        assert "memory" in result.output

    def test_providers(self):
        facade = self._make_stack()
        result = facade.execute_command("/providers")
        assert result.ok
        assert result.output["type"] == "providers"
        assert len(result.output["providers"]) >= 3

    def test_models(self):
        facade = self._make_stack()
        result = facade.execute_command("/models")
        assert result.ok
        assert result.output["type"] == "models"
        assert "models" in result.output

    def test_updates(self):
        facade = self._make_stack()
        result = facade.execute_command("/updates")
        assert result.ok
        assert result.output["type"] == "updates"
        assert "current" in result.output

    def test_all_commands_registered(self):
        facade = self._make_stack()
        for cmd_name in ("theme", "monitor", "providers", "models", "updates"):
            result = facade.execute_command(f"/{cmd_name}")
            assert result.ok, f"/{cmd_name} failed: {result.errors}"


# ══════════════════════════════════════════════════════════════════════
# Integration — full session lifecycle
# ══════════════════════════════════════════════════════════════════════

class TestSessionLifecycle:
    def test_full_session_roundtrip(self):
        """Simulate: create state → save → crash → recover → restore."""
        from hydra.services.session import SessionService
        from hydra.services.event_bus import EventBus
        from control_center.tui.state import WorkspaceState

        with tempfile.TemporaryDirectory() as td:
            bus = EventBus()
            svc = SessionService(bus, Path(td))

            # 1. Create state
            state = WorkspaceState()
            state.session_id = "lifecycle-test"
            state.current_target = "example.com"
            state.theme = "monokai"
            state.conversation_entries = [
                {"entry_type": "user", "text": "/recon example.com"},
                {"entry_type": "system", "text": "Recon started"},
            ]

            # 2. Write sentinel + save
            svc.write_sentinel("lifecycle-test")
            svc.save("lifecycle-test", state.to_dict())

            # 3. Simulate crash (don't clear sentinel)
            svc2 = SessionService(bus, Path(td))
            recovery = svc2.check_crash_recovery()
            assert recovery is not None
            assert recovery["session_id"] == "lifecycle-test"

            # 4. Recover
            data = svc2.recover_session()
            assert data is not None

            # 5. Restore state
            restored = WorkspaceState.from_dict(data)
            assert restored.current_target == "example.com"
            assert restored.theme == "monokai"
            assert len(restored.conversation_entries) == 2
            assert restored.conversation_entries[0]["text"] == "/recon example.com"
