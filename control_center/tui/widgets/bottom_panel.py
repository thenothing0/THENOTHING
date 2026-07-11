"""Bottom panel — tool output, coverage, and progress views.

Docked below the conversation. Toggled with Ctrl+J.
Modes: output | coverage | progress
"""

from __future__ import annotations

from rich.text import Text
from textual.widgets import RichLog


class BottomPanel(RichLog):
    """Resizable bottom panel for tool output and status."""

    DEFAULT_CSS = """
    BottomPanel {
        height: 12;
        background: #0d1117;
        border-top: solid #30363d;
        display: none;
    }
    BottomPanel.open {
        display: block;
    }
    """

    def toggle(self):
        if self.has_class("open"):
            self.remove_class("open")
        else:
            self.add_class("open")

    def add_tool_output(self, tool: str, output: str):
        self.write(Text.from_markup(f"[bold green]{tool}[/]"))
        self.write(output)

    def add_progress(self, tool: str, pct: float, msg: str = ""):
        bar_len = 20
        filled = int(pct * bar_len)
        bar = "[green]" + "█" * filled + "[/][dim]" + "░" * (bar_len - filled) + "[/]"
        self.write(Text.from_markup(f"  {tool}: {bar} {pct*100:.0f}% {msg}"))

    def show_coverage(self, summary: dict):
        self.clear()
        total = summary.get("total", 0)
        tested = summary.get("tested", 0)
        pct = summary.get("coverage_pct", 0)
        self.write(Text.from_markup(
            f"[bold cyan]Coverage[/]\n"
            f"  Total:   {total}\n"
            f"  Tested:  {tested}\n"
            f"  Passed:  {summary.get('passed', 0)}\n"
            f"  Failed:  {summary.get('failed', 0)}\n"
            f"  Coverage: {pct:.1f}%\n"
            f"  Risk:     {summary.get('risk_score', 0):.1f}"
        ))
        self.add_class("open")
