"""Health registry: register per-service health checks and aggregate status."""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable

logger = logging.getLogger("hydra.observability.health")


class HealthRegistry:
    """Registry of named health-check callables.

    Each callable should return a dict with at least ``{"status": "healthy"}``.
    Services that don't support health checks are simply not registered —
    the registry never forces initialization or assumes availability.
    """

    def __init__(self) -> None:
        self._checks: dict[str, Callable[[], dict[str, Any]]] = {}
        self._lock = threading.Lock()

    def register(self, name: str, check_fn: Callable[[], dict[str, Any]]) -> None:
        """Register a health-check callable under *name*."""
        with self._lock:
            self._checks[name] = check_fn

    def check_all(self) -> dict[str, Any]:
        """Run every registered check and return an aggregate report.

        Each check is called synchronously; failures are caught and reported
        as ``"unavailable"`` without propagating.
        """
        with self._lock:
            checks = dict(self._checks)

        results: dict[str, dict[str, Any]] = {}
        overall = "healthy"

        for name, fn in checks.items():
            t0 = time.perf_counter()
            try:
                result = fn()
                latency_ms = round((time.perf_counter() - t0) * 1000, 2)
                status = result.get("status", "healthy") if isinstance(result, dict) else "healthy"
                results[name] = {
                    "status": status,
                    "latency_ms": latency_ms,
                    "detail": result,
                }
                if status == "degraded" and overall == "healthy":
                    overall = "degraded"
                elif status == "unavailable":
                    overall = "degraded"
            except Exception as exc:
                latency_ms = round((time.perf_counter() - t0) * 1000, 2)
                results[name] = {
                    "status": "unavailable",
                    "latency_ms": latency_ms,
                    "error": str(exc),
                }
                overall = "degraded"
                logger.debug("health check %s failed: %s", name, exc)

        return {
            "status": overall,
            "services": results,
            "checked_at": time.time(),
        }


health = HealthRegistry()
