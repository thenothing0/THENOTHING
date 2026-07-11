"""
Capability Registry — central dynamic discovery for all HYDRA capabilities.

Everything registers here: commands, panels, widgets, guards, providers,
plugins, workflows, knowledge packs, agents, MCP tools. The TUI (or any
other client) queries this registry to discover what's available — it never
hardcodes capabilities.
"""

import logging
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

logger = logging.getLogger("hydra.registry")


class CapabilityType(str, Enum):
    COMMAND = "command"
    PANEL = "panel"
    WIDGET = "widget"
    GUARD = "guard"
    PROVIDER = "provider"
    PLUGIN = "plugin"
    WORKFLOW = "workflow"
    KNOWLEDGE_PACK = "knowledge_pack"
    AGENT = "agent"
    MCP_TOOL = "mcp_tool"


@dataclass
class Capability:
    type: CapabilityType
    id: str
    name: str
    description: str = ""
    source: str = "builtin"
    metadata: dict[str, Any] = field(default_factory=dict)
    factory: Callable | None = None


class CapabilityRegistry:
    """Thread-safe registry of all HYDRA capabilities."""

    def __init__(self):
        self._capabilities: dict[str, Capability] = {}
        self._lock = threading.Lock()

    def register(self, capability: Capability) -> None:
        with self._lock:
            if capability.id in self._capabilities:
                existing = self._capabilities[capability.id]
                logger.debug(
                    "capability %s overridden: %s -> %s",
                    capability.id, existing.source, capability.source,
                )
            self._capabilities[capability.id] = capability
            logger.debug("registered %s:%s", capability.type, capability.id)

    def unregister(self, capability_id: str) -> None:
        with self._lock:
            self._capabilities.pop(capability_id, None)

    def get(self, capability_id: str) -> Capability | None:
        return self._capabilities.get(capability_id)

    def has(self, capability_id: str) -> bool:
        return capability_id in self._capabilities

    def query(
        self,
        type: CapabilityType | None = None,
        source: str | None = None,
    ) -> list[Capability]:
        results = list(self._capabilities.values())
        if type is not None:
            results = [c for c in results if c.type == type]
        if source is not None:
            results = [c for c in results if c.source == source]
        return results

    def count(self, type: CapabilityType | None = None) -> int:
        if type is None:
            return len(self._capabilities)
        return sum(1 for c in self._capabilities.values() if c.type == type)

    def clear(self) -> None:
        with self._lock:
            self._capabilities.clear()
