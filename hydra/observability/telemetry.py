"""Thread-safe telemetry: counters, gauges, and timers with percentile stats."""

from __future__ import annotations

import statistics
import threading
import time
from collections import deque
from contextlib import contextmanager
from typing import Any, Iterator


class Telemetry:
    """Lightweight in-process telemetry collector.

    * ``counter(name)`` — monotonic increment
    * ``gauge(name, value)`` — point-in-time value
    * ``timer(name)`` — context manager recording latency in milliseconds

    All operations are thread-safe. Timer history is bounded to the most
    recent 1 000 observations per metric (no unbounded growth).
    """

    def __init__(self, *, timer_maxlen: int = 1000) -> None:
        self._counters: dict[str, int] = {}
        self._gauges: dict[str, float] = {}
        self._timers: dict[str, deque[float]] = {}
        self._timer_maxlen = timer_maxlen
        self._lock = threading.Lock()

    # ── Writers ──────────────────────────────────────────────

    def counter(self, name: str, delta: int = 1) -> None:
        with self._lock:
            self._counters[name] = self._counters.get(name, 0) + delta

    def gauge(self, name: str, value: float) -> None:
        with self._lock:
            self._gauges[name] = value

    @contextmanager
    def timer(self, name: str) -> Iterator[None]:
        t0 = time.perf_counter()
        try:
            yield
        finally:
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            with self._lock:
                if name not in self._timers:
                    self._timers[name] = deque(maxlen=self._timer_maxlen)
                self._timers[name].append(elapsed_ms)

    # ── Readers ──────────────────────────────────────────────

    def snapshot(self) -> dict[str, Any]:
        """Return all counters, gauges, and timer stats."""
        with self._lock:
            return {
                "counters": dict(self._counters),
                "gauges": dict(self._gauges),
                "timers": {
                    name: self._compute_stats(vals)
                    for name, vals in self._timers.items()
                },
            }

    def perf_stats(self, name: str) -> dict[str, float]:
        """Return percentile stats for a single timer metric."""
        with self._lock:
            vals = self._timers.get(name)
            if not vals:
                return {}
            return self._compute_stats(vals)

    def all_perf_stats(self) -> dict[str, dict[str, float]]:
        """Return percentile stats for all timer metrics."""
        with self._lock:
            return {
                name: self._compute_stats(vals)
                for name, vals in self._timers.items()
            }

    # ── Internal ─────────────────────────────────────────────

    @staticmethod
    def _compute_stats(vals: deque[float]) -> dict[str, float]:
        if not vals:
            return {}
        sorted_vals = sorted(vals)
        n = len(sorted_vals)
        return {
            "count": n,
            "mean": round(statistics.mean(sorted_vals), 3),
            "min": round(sorted_vals[0], 3),
            "max": round(sorted_vals[-1], 3),
            "p50": round(sorted_vals[n // 2], 3),
            "p95": round(sorted_vals[int(n * 0.95)], 3) if n >= 2 else round(sorted_vals[-1], 3),
            "p99": round(sorted_vals[int(n * 0.99)], 3) if n >= 2 else round(sorted_vals[-1], 3),
        }


telemetry = Telemetry()
