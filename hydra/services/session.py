"""Session service — persistent workspace sessions with crash recovery.

Capabilities:
  - Auto-save workspace state on interval and key events
  - Crash sentinel: detects unclean shutdown and offers recovery
  - Full state serialization: context, conversation, workflow, panels, nav
  - Session listing, deletion, and explicit save/restore
"""

from __future__ import annotations

import json
import logging
import time
import threading
from pathlib import Path
from typing import Any

from hydra.services.base import BaseService

logger = logging.getLogger("hydra.services.session")

_SENTINEL_NAME = ".hydra_session_active"
_AUTO_SAVE_FILE = ".hydra_autosave.json"


class SessionService(BaseService):

    def __init__(self, event_bus, data_dir=None):
        super().__init__(event_bus, data_dir)
        self._sessions_dir = self._data_dir / "sessions"
        self._sessions_dir.mkdir(parents=True, exist_ok=True)
        self._auto_save_timer: threading.Timer | None = None
        self._auto_save_interval: float = 30.0
        self._current_session_id: str | None = None

    # ── Crash recovery ──

    def write_sentinel(self, session_id: str):
        sentinel = self._data_dir / _SENTINEL_NAME
        sentinel.write_text(json.dumps({
            "session_id": session_id,
            "pid": __import__("os").getpid(),
            "timestamp": time.time(),
        }))
        self._current_session_id = session_id

    def clear_sentinel(self):
        sentinel = self._data_dir / _SENTINEL_NAME
        if sentinel.exists():
            sentinel.unlink(missing_ok=True)

    def check_crash_recovery(self) -> dict[str, Any] | None:
        """Check if a previous session crashed (sentinel exists without clean exit)."""
        sentinel = self._data_dir / _SENTINEL_NAME
        if not sentinel.exists():
            return None
        try:
            info = json.loads(sentinel.read_text())
            sid = info.get("session_id", "")
            autosave = self._data_dir / _AUTO_SAVE_FILE
            if autosave.exists():
                return {
                    "session_id": sid,
                    "timestamp": info.get("timestamp", 0),
                    "has_autosave": True,
                }
            saved = self._session_path(sid)
            if saved.exists():
                return {
                    "session_id": sid,
                    "timestamp": info.get("timestamp", 0),
                    "has_autosave": False,
                }
        except Exception:
            pass
        sentinel.unlink(missing_ok=True)
        return None

    def recover_session(self) -> dict[str, Any] | None:
        """Load the crashed session's state."""
        autosave = self._data_dir / _AUTO_SAVE_FILE
        if autosave.exists():
            try:
                data = json.loads(autosave.read_text())
                self.clear_sentinel()
                autosave.unlink(missing_ok=True)
                self._emit("session.recovered", {"session_id": data.get("session_id", "")})
                return data
            except Exception:
                pass

        info = self.check_crash_recovery()
        if info:
            return self.load(info["session_id"])
        return None

    # ── Auto-save ──

    def start_auto_save(self, interval: float = 30.0, state_callback=None):
        """Start periodic auto-save. state_callback returns the current state dict."""
        self._auto_save_interval = interval
        self._state_callback = state_callback
        if interval > 0 and state_callback:
            self._schedule_auto_save()

    def stop_auto_save(self):
        if self._auto_save_timer:
            self._auto_save_timer.cancel()
            self._auto_save_timer = None

    def _schedule_auto_save(self):
        self._auto_save_timer = threading.Timer(
            self._auto_save_interval, self._do_auto_save
        )
        self._auto_save_timer.daemon = True
        self._auto_save_timer.start()

    def _do_auto_save(self):
        try:
            if hasattr(self, "_state_callback") and self._state_callback:
                state = self._state_callback()
                if state:
                    autosave = self._data_dir / _AUTO_SAVE_FILE
                    autosave.write_text(json.dumps(state, default=str))
        except Exception as e:
            logger.debug("Auto-save failed: %s", e)
        finally:
            if self._auto_save_interval > 0:
                self._schedule_auto_save()

    # ── Explicit save/load ──

    def save(self, session_id: str, data: dict[str, Any]) -> dict[str, Any]:
        try:
            path = self._session_path(session_id)
            data["session_id"] = session_id
            data["saved_at"] = time.time()
            path.write_text(json.dumps(data, default=str, indent=2))
            self._emit("session.saved", {"session_id": session_id})
            return {"session_id": session_id}
        except Exception as e:
            return {"error": str(e)}

    def load(self, session_id: str) -> dict[str, Any] | None:
        try:
            path = self._session_path(session_id)
            if path.exists():
                data = json.loads(path.read_text())
                self._emit("session.loaded", {"session_id": session_id})
                return data
        except Exception:
            pass
        return None

    def list_sessions(self) -> list[dict[str, Any]]:
        results = []
        for p in sorted(self._sessions_dir.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
            try:
                data = json.loads(p.read_text())
                results.append({
                    "session_id": data.get("session_id", p.stem),
                    "saved_at": data.get("saved_at", 0),
                    "target": data.get("current_target", ""),
                    "engagement": data.get("current_engagement_id", ""),
                })
            except Exception:
                results.append({"session_id": p.stem, "saved_at": 0})
        return results

    def delete(self, session_id: str) -> dict[str, Any]:
        try:
            path = self._session_path(session_id)
            if path.exists():
                path.unlink()
            return {"deleted": session_id}
        except Exception as e:
            return {"error": str(e)}

    # ── Full workspace serialization ──

    @staticmethod
    def serialize_workspace(state) -> dict[str, Any]:
        """Serialize a WorkspaceState into a restorable dict."""
        return {
            "current_engagement_id": state.current_engagement_id,
            "current_workflow_id": state.current_workflow_id,
            "current_target": state.current_target,
            "session_id": state.session_id,
            "current_provider": state.current_provider,
            "current_model": state.current_model,
            "context_drawer_open": state.context_drawer_open,
            "context_drawer_content": state.context_drawer_content,
            "bottom_panel_open": state.bottom_panel_open,
            "bottom_panel_mode": state.bottom_panel_mode,
            "sidebar_visible": state.sidebar_visible,
            "selected_finding_id": state.selected_finding_id,
            "selected_tool": state.selected_tool,
            "selected_wiki_page": state.selected_wiki_page,
            "nav_history": list(state.nav_history),
        }

    @staticmethod
    def restore_workspace(state, data: dict[str, Any]):
        """Restore a WorkspaceState from a serialized dict."""
        for key in [
            "current_engagement_id", "current_workflow_id", "current_target",
            "session_id", "current_provider", "current_model",
            "context_drawer_open", "context_drawer_content",
            "bottom_panel_open", "bottom_panel_mode", "sidebar_visible",
            "selected_finding_id", "selected_tool", "selected_wiki_page",
        ]:
            if key in data:
                setattr(state, key, data[key])
        if "nav_history" in data:
            state.nav_history = list(data["nav_history"])

    # ── Internal ──

    def _session_path(self, session_id: str) -> Path:
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in session_id)
        return self._sessions_dir / f"{safe}.json"
