"""Status bar — the always-visible bottom metrics line.

Shows Workspace · Profile · Memory · CPU · Workers · Events/s · Scope ·
Connection. A dumb widget: the App's single 1s monitor refresh sets these
reactives from ``facade.get_monitor_snapshot()``; ``render`` never calls the
backend.
"""

from __future__ import annotations

from rich.text import Text
from textual.reactive import reactive
from textual.widget import Widget


class StatusBar(Widget):
    """Single-line status bar docked at the very bottom."""

    workspace: reactive[str] = reactive("default")
    profile: reactive[str] = reactive("")
    memory_mb: reactive[float] = reactive(0.0)
    cpu_load: reactive[float] = reactive(0.0)
    worker_count: reactive[int] = reactive(0)
    events_per_sec: reactive[float] = reactive(0.0)
    scope: reactive[str] = reactive("")
    connected: reactive[bool] = reactive(True)

    def render(self):
        parts: list[str] = [f"[bold]{self.workspace or 'default'}[/]"]
        if self.profile:
            parts.append(self.profile)
        if self.memory_mb:
            parts.append(f"{self.memory_mb:.0f}MB")
        parts.append(f"load {self.cpu_load:.1f}")
        if self.worker_count:
            parts.append(f"[#9ece6a]⟳ {self.worker_count}[/]")
        parts.append(f"{self.events_per_sec:.0f}/s")
        if self.scope:
            parts.append(f"scope {self.scope}")
        parts.append("[#9ece6a]●[/]" if self.connected else "[#f7768e]●[/]")
        return Text.from_markup(" [dim]·[/] ".join(parts))
