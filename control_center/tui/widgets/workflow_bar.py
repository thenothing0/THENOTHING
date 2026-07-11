"""Workflow bar — shows pentest lifecycle state inline.

The 9-state lifecycle: scope → recon → enumeration → validation →
exploitation → evidence → coverage_review → reporting → done
"""

from __future__ import annotations

from rich.text import Text
from textual.reactive import reactive
from textual.widget import Widget

WORKFLOW_STATES = [
    "scope", "recon", "enumeration", "validation",
    "exploitation", "evidence", "coverage_review", "reporting", "done",
]


class WorkflowBar(Widget):
    """Horizontal workflow state indicator."""

    DEFAULT_CSS = """
    WorkflowBar {
        height: 1;
        background: #161b22;
        padding: 0 1;
    }
    """

    current_state: reactive[str] = reactive("")

    def render(self):
        if not self.current_state:
            return Text.from_markup("[dim]No active workflow[/]")

        parts = []
        for state in WORKFLOW_STATES:
            if state == self.current_state:
                parts.append(f"[bold green]{state}[/]")
            elif WORKFLOW_STATES.index(state) < WORKFLOW_STATES.index(self.current_state):
                parts.append(f"[dim]{state}[/]")
            else:
                parts.append(f"[dim white]{state}[/]")

        return Text.from_markup(" → ".join(parts))
