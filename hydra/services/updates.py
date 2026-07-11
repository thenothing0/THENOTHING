"""UpdateChecker — built-in update checking infrastructure.

Checks for new versions without blocking startup. Results are cached
for 24 hours. Never auto-downloads or auto-installs.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from hydra.services.base import BaseService

logger = logging.getLogger("hydra.services.updates")

CURRENT_VERSION = "7.1.0"
_CACHE_TTL = 86400  # 24 hours


class UpdateChecker(BaseService):
    """Non-blocking version check with local cache."""

    def __init__(self, event_bus, data_dir=None):
        super().__init__(event_bus, data_dir)
        self._cache_file = self._data_dir / ".update_check_cache.json"

    def get_current_version(self) -> str:
        return CURRENT_VERSION

    def check(self, force: bool = False) -> dict[str, Any]:
        """Check for updates. Returns cached result if recent enough."""
        if not force:
            cached = self._read_cache()
            if cached:
                return cached

        result = self._do_check()
        self._write_cache(result)
        return result

    def get_cached_result(self) -> dict[str, Any] | None:
        return self._read_cache()

    def _do_check(self) -> dict[str, Any]:
        """Perform the actual version check."""
        try:
            import urllib.request
            url = "https://api.github.com/repos/thenothing/hydra/releases/latest"
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read())
                latest = data.get("tag_name", "").lstrip("v")
                return {
                    "current": CURRENT_VERSION,
                    "latest": latest,
                    "update_available": self._is_newer(latest, CURRENT_VERSION),
                    "url": data.get("html_url", ""),
                    "checked_at": time.time(),
                    "error": None,
                }
        except Exception as e:
            return {
                "current": CURRENT_VERSION,
                "latest": None,
                "update_available": False,
                "url": "",
                "checked_at": time.time(),
                "error": str(e),
            }

    def _read_cache(self) -> dict[str, Any] | None:
        try:
            if self._cache_file.exists():
                data = json.loads(self._cache_file.read_text())
                if time.time() - data.get("checked_at", 0) < _CACHE_TTL:
                    return data
        except Exception:
            pass
        return None

    def _write_cache(self, result: dict[str, Any]):
        try:
            self._cache_file.write_text(json.dumps(result))
        except Exception:
            pass

    @staticmethod
    def _is_newer(latest: str, current: str) -> bool:
        try:
            def parts(v: str) -> tuple[int, ...]:
                return tuple(int(x) for x in v.split("."))
            return parts(latest) > parts(current)
        except (ValueError, TypeError):
            return False
