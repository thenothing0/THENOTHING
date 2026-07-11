"""Sidebar — minimal navigation panel.

Shows engagement context, recent findings count, and quick links.
Toggled with Ctrl+B.
"""

from __future__ import annotations

from rich.text import Text
from textual.widget import Widget
from textual.reactive import reactive


class Sidebar(Widget):
    """Narrow left sidebar with context info."""

    DEFAULT_CSS = """
    Sidebar {
        width: 28;
        background: $panel;
        border-right: solid $accent;
        padding: 1;
    }
    """

    engagement_name: reactive[str] = reactive("")
    target: reactive[str] = reactive("")
    findings_count: reactive[int] = reactive(0)
    tools_running: reactive[int] = reactive(0)

    def render(self):
        lines = [
            "[bold cyan]HYDRA[/] [dim]v7.1[/]",
            "",
        ]

        if self.engagement_name:
            lines.append("[bold]Engagement[/]")
            lines.append(f"  {self.engagement_name}")
        else:
            lines.append("[dim]No engagement[/]")

        if self.target:
            lines.append("\n[bold]Target[/]")
            lines.append(f"  {self.target}")

        lines.append(f"\n[bold]Findings[/]  {self.findings_count}")
        if self.tools_running:
            lines.append(f"[bold]Running[/]   [green]{self.tools_running}[/]")

        lines.extend([
            "",
            "[dim]─── Quick ───[/]",
            "[dim]/help[/]       commands",
            "[dim]/status[/]     health",
            "[dim]/tools[/]      installed",
            "[dim]/findings[/]   list",
            "[dim]/knowledge[/]  wiki",
        ])

        return Text.from_markup("\n".join(lines))
