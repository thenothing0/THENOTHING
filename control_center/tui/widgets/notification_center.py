"""NotificationCenter — overlay history of in-app notifications (Ctrl+N).

The App raises non-interrupting toasts via Textual's native ``App.notify`` and
mirrors them here for history. Bounded to ≤1000 entries; renders the most recent
into a single ``Static`` (two widgets total) so the overlay stays cheap even with
a full backlog. Hidden by default.
"""

from __future__ import annotations

from collections import deque

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.widgets import Static

MAX_ITEMS = 1000
_SHOWN = 200

_SEV_ICON = {
    "information": "[#7dcfff]ℹ[/]",
    "success": "[#9ece6a]✓[/]",
    "warning": "[#e0af68]▲[/]",
    "error": "[#f7768e]✗[/]",
}


class NotificationCenter(VerticalScroll):
    """Scrollable notification history overlay."""

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._items: deque[tuple[str, str]] = deque(maxlen=MAX_ITEMS)

    def compose(self) -> ComposeResult:
        yield Static("[bold]Notifications[/]  [dim]Ctrl+N / Esc to close[/]", id="notif-title")
        yield Static("[dim]No notifications yet.[/]", id="notif-body")

    def add(self, message: str, severity: str = "information") -> None:
        self._items.appendleft((severity, message))
        self._render_items()

    def _render_items(self) -> None:
        try:
            body = self.query_one("#notif-body", Static)
        except Exception:
            return
        if not self._items:
            body.update("[dim]No notifications yet.[/]")
            return
        lines = []
        for severity, message in list(self._items)[:_SHOWN]:
            icon = _SEV_ICON.get(severity, _SEV_ICON["information"])
            safe = str(message).replace("[", r"\[")
            lines.append(f"{icon} {safe}")
        body.update(Text.from_markup("\n".join(lines)))
