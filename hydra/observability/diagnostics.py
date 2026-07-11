"""Crash diagnostics: capture, store, and retrieve recent exception bundles."""

from __future__ import annotations

import sys
import threading
import time
import traceback
from collections import deque
from typing import Any

from hydra.observability.logging import get_correlation_id


class DiagnosticCapture:
    """Rolling buffer of recent crash bundles for post-mortem analysis.

    Never swallows or suppresses exceptions — only records metadata.
    """

    def __init__(self, *, maxlen: int = 50) -> None:
        self._bundles: deque[dict[str, Any]] = deque(maxlen=maxlen)
        self._lock = threading.Lock()

    def capture(
        self, exc: BaseException, context: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Build a diagnostic bundle from an exception and store it."""
        bundle: dict[str, Any] = {
            "timestamp": time.time(),
            "correlation_id": get_correlation_id(),
            "exception_type": type(exc).__qualname__,
            "exception_message": str(exc),
            "traceback": traceback.format_exception(type(exc), exc, exc.__traceback__),
            "thread": threading.current_thread().name,
            "context": context or {},
        }
        with self._lock:
            self._bundles.append(bundle)
        return bundle

    def get_recent(self, n: int = 10) -> list[dict[str, Any]]:
        """Return the *n* most recent crash bundles (newest first)."""
        with self._lock:
            items = list(self._bundles)
        return list(reversed(items[-n:]))

    def install_hook(self) -> None:
        """Install as ``sys.excepthook`` to capture unhandled exceptions.

        The original hook is preserved and called after recording.
        """
        original = sys.excepthook

        def _hook(exc_type, exc_value, exc_tb):
            self.capture(exc_value)
            original(exc_type, exc_value, exc_tb)

        sys.excepthook = _hook


diagnostics = DiagnosticCapture()
