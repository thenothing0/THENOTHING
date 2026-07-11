"""ProgressPanel — one background job row.

Shows the job name, a `ProgressBar` (indeterminate when the backend reports no
percentage), and live elapsed time. Honest degradation: with no real total it
pulses + counts elapsed; a real total enables a determinate bar + ETA. Elapsed
is advanced by the App's single 1s tick (``tick``); the widget does no I/O.
"""

from __future__ import annotations

import time

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import ProgressBar, Static


class ProgressPanel(Horizontal):
    """A single running-task row."""

    DEFAULT_CSS = """
    ProgressPanel { height: 1; }
    ProgressPanel .job-name { width: 24; content-align: left middle; }
    ProgressPanel .job-elapsed { width: 8; content-align: right middle; color: $text-muted; }
    ProgressPanel ProgressBar { width: 1fr; }
    """

    def __init__(self, key: str, name: str, total: float | None = None, **kwargs) -> None:
        super().__init__(**kwargs)
        self.key = key
        self._name = name
        self._total = total
        self._start = time.monotonic()

    def compose(self) -> ComposeResult:
        yield Static(self._name, classes="job-name")
        yield ProgressBar(total=self._total, show_eta=bool(self._total), id="bar")
        yield Static("0.0s", classes="job-elapsed")

    def advance(self, amount: float = 1) -> None:
        if self._total:
            self.query_one("#bar", ProgressBar).advance(amount)

    def tick(self) -> None:
        elapsed = time.monotonic() - self._start
        self.query_one(".job-elapsed", Static).update(f"{elapsed:.1f}s")
