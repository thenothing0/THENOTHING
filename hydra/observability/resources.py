"""Resource monitor: on-demand system resource snapshots (no polling)."""

from __future__ import annotations

import gc
import os
import threading
from typing import Any


class ResourceMonitor:
    """Collects system resource metrics on demand.

    No background threads, no polling, no timers. Every call to
    :meth:`snapshot` reads current values directly. Gracefully degrades
    on unsupported platforms.
    """

    def snapshot(self) -> dict[str, Any]:
        return {
            "memory": self._memory(),
            "cpu": self._cpu(),
            "threads": threading.active_count(),
            "gc": self._gc_stats(),
            "open_fds": self._open_fds(),
            "pid": os.getpid(),
        }

    # ── Internal ─────────────────────────────────────────────

    @staticmethod
    def _memory() -> dict[str, Any]:
        try:
            import resource
            rusage = resource.getrusage(resource.RUSAGE_SELF)
            rss_kb = rusage.ru_maxrss
            if hasattr(os, "uname") and os.uname().sysname == "Darwin":
                rss_kb = rss_kb // 1024
            return {"rss_mb": round(rss_kb / 1024, 1), "source": "resource"}
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

    @staticmethod
    def _cpu() -> dict[str, Any]:
        try:
            load1, load5, load15 = os.getloadavg()
            return {
                "load_1m": round(load1, 2),
                "load_5m": round(load5, 2),
                "load_15m": round(load15, 2),
            }
        except (OSError, AttributeError):
            return {"load_1m": 0, "load_5m": 0, "load_15m": 0}

    @staticmethod
    def _gc_stats() -> list[dict[str, Any]]:
        try:
            return [
                {
                    "collections": s.get("collections", 0),
                    "collected": s.get("collected", 0),
                    "uncollectable": s.get("uncollectable", 0),
                }
                for s in gc.get_stats()
            ]
        except Exception:
            return []

    @staticmethod
    def _open_fds() -> int:
        try:
            return len(os.listdir(f"/proc/{os.getpid()}/fd"))
        except Exception:
            return -1


resources = ResourceMonitor()
