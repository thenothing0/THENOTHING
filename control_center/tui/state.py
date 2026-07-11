"""WorkspaceState — centralized reactive state with serialization.

Widgets observe these fields via Textual's `watch_*` methods.
No widget owns state; all state lives here.
Serializable for session persistence and crash recovery.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class WorkspaceState:
    """Mutable state bag — the HydraApp owns the single instance."""

    # Session context
    current_engagement_id: str | None = None
    current_workflow_id: str | None = None
    current_target: str | None = None
    session_id: str | None = None

    # AI context
    current_provider: str = "anthropic"
    current_model: str = "claude-sonnet-4"

    # UI state
    context_drawer_open: bool = False
    context_drawer_content: str | None = None
    context_drawer_data: dict | None = None
    bottom_panel_open: bool = False
    bottom_panel_mode: str = "output"
    sidebar_visible: bool = True  # state default kept True for back-compat; the
    # app hides the sidebar on a fresh launch (chat-first), restoring it visible
    # only when a saved session had it open.
    task_panel_open: bool = False
    notification_open: bool = False
    sidebar_width: int = 32

    # Workspace / profile
    current_workspace: str = "default"
    current_profile: str = ""

    # Pins, bookmarks, recents
    pinned_sessions: list[str] = field(default_factory=list)
    bookmarks: list[str] = field(default_factory=list)
    recent_targets: list[str] = field(default_factory=list)
    search_history: list[str] = field(default_factory=list)

    # Selection
    selected_finding_id: str | None = None
    selected_tool: str | None = None
    selected_wiki_page: str | None = None

    # Running operations
    active_tools: list[str] = field(default_factory=list)
    pending_approvals: list[dict] = field(default_factory=list)

    # Navigation history
    nav_history: list[str] = field(default_factory=list)

    # Conversation log (for session restore)
    conversation_entries: list[dict[str, Any]] = field(default_factory=list)

    # Theme
    theme: str = "dark"

    def to_dict(self) -> dict[str, Any]:
        """Serialize state for session persistence."""
        return {
            "current_engagement_id": self.current_engagement_id,
            "current_workflow_id": self.current_workflow_id,
            "current_target": self.current_target,
            "session_id": self.session_id,
            "current_provider": self.current_provider,
            "current_model": self.current_model,
            "context_drawer_open": self.context_drawer_open,
            "context_drawer_content": self.context_drawer_content,
            "bottom_panel_open": self.bottom_panel_open,
            "bottom_panel_mode": self.bottom_panel_mode,
            "sidebar_visible": self.sidebar_visible,
            "task_panel_open": self.task_panel_open,
            "notification_open": self.notification_open,
            "sidebar_width": self.sidebar_width,
            "current_workspace": self.current_workspace,
            "current_profile": self.current_profile,
            "pinned_sessions": list(self.pinned_sessions[-100:]),
            "bookmarks": list(self.bookmarks[-100:]),
            "recent_targets": list(self.recent_targets[-20:]),
            "search_history": list(self.search_history[-200:]),
            "selected_finding_id": self.selected_finding_id,
            "selected_tool": self.selected_tool,
            "selected_wiki_page": self.selected_wiki_page,
            "nav_history": list(self.nav_history[-50:]),
            "conversation_entries": self.conversation_entries[-200:],
            "theme": self.theme,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WorkspaceState:
        """Restore state from a serialized dict."""
        state = cls()
        for key in [
            "current_engagement_id", "current_workflow_id", "current_target",
            "session_id", "current_provider", "current_model",
            "context_drawer_open", "context_drawer_content",
            "bottom_panel_open", "bottom_panel_mode", "sidebar_visible",
            "task_panel_open", "notification_open", "sidebar_width",
            "current_workspace", "current_profile",
            "selected_finding_id", "selected_tool", "selected_wiki_page",
            "theme",
        ]:
            if key in data:
                setattr(state, key, data[key])
        for list_key in ["nav_history", "conversation_entries", "pinned_sessions",
                         "bookmarks", "recent_targets", "search_history"]:
            if list_key in data:
                setattr(state, list_key, list(data[list_key]))
        return state
