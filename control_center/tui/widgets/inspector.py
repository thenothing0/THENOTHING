"""Inspector — overlay panel for deep-diving into specific items.

Shows detailed raw data, JSON views, or debug information.
Toggled with Ctrl+I.
"""

from __future__ import annotations

import json

from rich.syntax import Syntax
from textual.containers import VerticalScroll
from textual.widgets import Static


class Inspector(VerticalScroll):
    """Full-width overlay for raw data inspection."""

    DEFAULT_CSS = """
    Inspector {
        background: #0d1117;
        border: solid #30363d;
        padding: 1 2;
        display: none;
        layer: overlay;
        width: 100%;
        height: 100%;
    }
    Inspector.open {
        display: block;
    }
    Inspector .inspector-title {
        text-style: bold;
        color: #58a6ff;
        margin-bottom: 1;
    }
    """

    def inspect_json(self, title: str, data):
        """Display raw JSON data."""
        self._clear_content()
        self.mount(Static(f"[bold cyan]{title}[/]  [dim]Press Ctrl+I or Escape to close[/]",
                          classes="inspector-title"))
        try:
            formatted = json.dumps(data, indent=2, default=str)
            self.mount(Static(Syntax(formatted, "json", theme="monokai")))
        except Exception:
            self.mount(Static(str(data)))
        self.add_class("open")

    def inspect_text(self, title: str, text: str):
        """Display raw text."""
        self._clear_content()
        self.mount(Static(f"[bold cyan]{title}[/]  [dim]Press Ctrl+I or Escape to close[/]",
                          classes="inspector-title"))
        self.mount(Static(text))
        self.add_class("open")

    def close(self):
        self.remove_class("open")

    def toggle(self):
        if self.has_class("open"):
            self.close()
        else:
            pass  # only open with specific content

    def _clear_content(self):
        for child in list(self.children):
            child.remove()
