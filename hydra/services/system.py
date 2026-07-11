"""SystemService — config, health, tool availability."""

import logging
import subprocess
from typing import Any

from hydra.services.base import BaseService

logger = logging.getLogger("hydra.services.system")

CORE_TOOLS = [
    "subfinder", "amass", "httpx", "nuclei", "ffuf", "katana",
    "gau", "dalfox", "sqlmap", "nmap", "nikto", "whatweb",
    "wafw00f", "dirsearch", "hakrawler", "gxss", "dnsx", "subzy",
]


class SystemService(BaseService):

    def get_health(self) -> dict[str, Any]:
        return {
            "healthy": True,
            "status": "healthy",
            "version": "7.1",
            "platform": "THENOTHING",
            "data_dir": str(self._data_dir),
        }

    def get_config_summary(self) -> dict[str, Any]:
        try:
            from hydra.config import get_config
            cfg = get_config()
            return {
                "ai_providers": [
                    p.name for p in (cfg.ai_providers if hasattr(cfg, "ai_providers") else [])
                ],
                "sandbox_enabled": getattr(cfg, "sandbox", None) is not None,
            }
        except Exception:
            return {"ai_providers": [], "sandbox_enabled": False}

    def check_tools(self) -> dict[str, bool]:
        results = {}
        for tool in CORE_TOOLS:
            try:
                subprocess.run(
                    ["which", tool], capture_output=True, timeout=5
                )
                results[tool] = True
            except Exception:
                results[tool] = False
        self._emit("tools.checked", {"tools": results})
        return results
