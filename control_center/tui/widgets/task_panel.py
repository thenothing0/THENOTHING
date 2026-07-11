"""TaskPanel — the collapsible background-task list (Ctrl+J).

Hidden by default. Running jobs show as :class:`ProgressPanel` rows; finished
jobs drop into a bounded history line list (≤500). The App drives it from worker
lifecycle: :meth:`add_job` on dispatch, :meth:`finish_job` on completion,
:meth:`tick` on the 1s refresh. No business logic here.
"""

from __future__ import annotations

from collections import deque

from textual.containers import VerticalScroll
from textual.widgets import Static

from control_center.tui.widgets.progress_panel import ProgressPanel

MAX_HISTORY = 500


class TaskPanel(VerticalScroll):
    """Live + recent background tasks."""

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._history: deque[str] = deque(maxlen=MAX_HISTORY)
        self._empty: Static | None = None

    def on_mount(self) -> None:
        self._empty = Static("[dim]No background tasks.[/]")
        self.mount(self._empty)

    def add_job(self, key: str, name: str, total: float | None = None) -> None:
        if self._empty is not None:
            self._empty.remove()
            self._empty = None
        self.mount(ProgressPanel(key, name, total=total))

    def finish_job(self, key: str, status: str = "done") -> None:
        icon = "[#9ece6a]✓[/]" if status == "done" else "[#f7768e]✗[/]"
        for panel in self.query(ProgressPanel):
            if panel.key == key:
                name = panel._name
                panel.remove()
                self._history.appendleft(f"{icon} {name}")
                self.mount(Static(f"{icon} [dim]{name}[/]"))
                break
        if not self.query(ProgressPanel) and self._empty is None:
            self._empty = Static("[dim]No background tasks.[/]")
            self.mount(self._empty)

    def tick(self) -> None:
        for panel in self.query(ProgressPanel):
            panel.tick()
