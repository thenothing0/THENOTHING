"""Tool output — streaming display for active tool execution.

Receives chunks via events and renders them progressively.
"""

from __future__ import annotations

from rich.text import Text
from textual.widgets import RichLog


class ToolOutput(RichLog):
    """Streaming output viewer for a single tool run."""

    DEFAULT_CSS = """
    ToolOutput {
        height: 1fr;
        background: #0d1117;
    }
    """

    def __init__(self, tool_name: str = "", **kw):
        super().__init__(**kw)
        self._tool_name = tool_name
        self._buffer: list[str] = []

    def on_mount(self):
        if self._tool_name:
            self.write(Text.from_markup(
                f"[bold cyan]Output: {self._tool_name}[/]\n"
                f"[dim]{'─' * 40}[/]"
            ))

    def append_chunk(self, chunk: str):
        """Append a streaming chunk."""
        self._buffer.append(chunk)
        self.write(chunk)

    def get_full_output(self) -> str:
        return "".join(self._buffer)

    def mark_complete(self, exit_code: int = 0):
        status = "[green]completed[/]" if exit_code == 0 else f"[red]failed (exit {exit_code})[/]"
        self.write(Text.from_markup(f"\n[dim]{'─' * 40}[/]\n{status}"))
