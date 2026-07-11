"""HeaderBar — the minimal top line: title + connection indicator.

Per the chat-first design the header carries nothing else; live metrics live in
the StatusBar. It is a dumb widget: the App sets ``connected`` (from the monitor
snapshot) on the 1s refresh; ``render`` never touches the backend.
"""

from __future__ import annotations

from rich.table import Table
from textual.reactive import reactive
from textual.widget import Widget


class HeaderBar(Widget):
    """Single-line header: ``HYDRA v2.0`` left, ``● Connected`` right."""

    connected: reactive[bool] = reactive(True)

    def render(self):
        grid = Table.grid(expand=True)
        grid.add_column(justify="left", ratio=1)
        grid.add_column(justify="right")
        if self.connected:
            dot = "[#9ece6a]●[/] [dim]Connected[/]"
        else:
            dot = "[#f7768e]●[/] [dim]Disconnected[/]"
        grid.add_row("[bold]HYDRA[/] [dim]v2.0[/]", dot)
        return grid
