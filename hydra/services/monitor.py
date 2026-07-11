"""RuntimeMonitor — system resource and platform health tracking.

Tracks: memory, CPU, active workers, task queues, MCP connections,
event throughput. All reads are non-blocking snapshots.
"""

from __future__ import annotations

import os
import threading
import time
from typing import Any

from hydra.observability.diagnostics import diagnostics
from hydra.observability.health import health as health_registry
from hydra.observability.resources import resources
from hydra.observability.telemetry import telemetry
from hydra.services.base import BaseService


class RuntimeMonitor(BaseService):
    """Collects runtime metrics without polling — called on demand or by timer."""

    def __init__(self, event_bus, data_dir=None):
        super().__init__(event_bus, data_dir)
        self._event_counts: dict[str, int] = {}
        self._event_lock = threading.Lock()
        self._start_time = time.monotonic()
        self._worker_count = 0
        self._task_count = 0
        self._mcp_connections = 0

        event_bus.subscribe("*", self._count_event)

    def _count_event(self, event):
        with self._event_lock:
            etype = event.type
            self._event_counts[etype] = self._event_counts.get(etype, 0) + 1

    # ── Snapshots ──

    def get_snapshot(self) -> dict[str, Any]:
        """Non-blocking full system snapshot."""
        return {
            "memory": self._get_memory(),
            "cpu": self._get_cpu(),
            "uptime_seconds": round(time.monotonic() - self._start_time, 1),
            "workers": self._worker_count,
            "tasks": self._task_count,
            "mcp_connections": self._mcp_connections,
            "events": self._get_event_stats(),
            "pid": os.getpid(),
            "telemetry": telemetry.snapshot(),
            "health": health_registry.check_all(),
            "resources": resources.snapshot(),
            "diagnostics": diagnostics.get_recent(5),
        }

    def get_memory(self) -> dict[str, Any]:
        return self._get_memory()

    def get_events(self) -> dict[str, Any]:
        return self._get_event_stats()

    # ── External updates ──

    def set_worker_count(self, count: int):
        self._worker_count = count

    def set_task_count(self, count: int):
        self._task_count = count

    def set_mcp_connections(self, count: int):
        self._mcp_connections = count

    # ── Internal ──

    def _get_memory(self) -> dict[str, Any]:
        try:
            import resource
            rusage = resource.getrusage(resource.RUSAGE_SELF)
            rss_kb = rusage.ru_maxrss
            if os.uname().sysname == "Darwin":
                rss_kb = rss_kb // 1024
            return {
                "rss_mb": round(rss_kb / 1024, 1),
                "source": "resource",
            }
        except Exception:
            pass
        try:
            with open(f"/proc/{os.getpid()}/status") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        kb = int(line.split()[1])
                        return {"rss_mb": round(kb / 1024, 1), "source": "proc"}
        except Exception:
            pass
        return {"rss_mb": 0, "source": "unavailable"}

    def _get_cpu(self) -> dict[str, Any]:
        try:
            load1, load5, load15 = os.getloadavg()
            return {
                "load_1m": round(load1, 2),
                "load_5m": round(load5, 2),
                "load_15m": round(load15, 2),
            }
        except (OSError, AttributeError):
            return {"load_1m": 0, "load_5m": 0, "load_15m": 0}

    def _get_event_stats(self) -> dict[str, Any]:
        with self._event_lock:
            total = sum(self._event_counts.values())
            top5 = sorted(
                self._event_counts.items(), key=lambda x: x[1], reverse=True
            )[:5]
            return {
                "total": total,
                "types": len(self._event_counts),
                "top": dict(top5),
                "throughput": round(
                    total / max(1, time.monotonic() - self._start_time), 1
                ),
            }
