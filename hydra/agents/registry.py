"""
AgentRegistry (Phase H) — declarative agent definitions + capability ownership.

Loads `capabilities/agent_catalog.yaml`. Each agent declares its responsibilities,
allowed capability categories (or an explicit capability scope), priority and expected
outputs. Ownership of concrete capabilities is resolved against the Capability Catalog
v2, keeping a single source of truth for "what exists".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

try:
    import yaml
except Exception:  # pragma: no cover
    yaml = None

from hydra.capabilities.capability_catalog import CapabilityCatalog, CapabilityEntry

_DEFAULT_CATALOG = Path(__file__).resolve().parents[2] / "capabilities" / "agent_catalog.yaml"


@dataclass
class AgentDefinition:
    agent_id: str
    priority: int = 5
    allowed_categories: List[str] = field(default_factory=list)
    responsibilities: str = ""
    expected_outputs: List[str] = field(default_factory=list)
    capability_scope: List[str] = field(default_factory=list)   # explicit ids; empty = by category
    knowledge_agent: bool = False    # operates on wiki/learning, not catalog tools

    def owned_capabilities(self, catalog: CapabilityCatalog) -> List[CapabilityEntry]:
        """Capabilities this agent owns: explicit scope if given, else all catalog
        capabilities in its allowed categories. Knowledge agents own none (they consume
        knowledge, not recon tools)."""
        if self.knowledge_agent:
            return []
        if self.capability_scope:
            return [c for c in (catalog.get(cid) for cid in self.capability_scope) if c]
        cats = set(self.allowed_categories)
        return [c for c in catalog.all() if c.category in cats]

    def to_dict(self) -> Dict:
        return {
            "agent_id": self.agent_id, "priority": self.priority,
            "allowed_categories": self.allowed_categories,
            "responsibilities": self.responsibilities,
            "expected_outputs": self.expected_outputs,
            "capability_scope": self.capability_scope,
            "knowledge_agent": self.knowledge_agent,
        }


class AgentRegistry:
    def __init__(self, catalog_path: Optional[Path | str] = None,
                 capability_catalog: Optional[CapabilityCatalog] = None):
        self.catalog_path = Path(catalog_path) if catalog_path else _DEFAULT_CATALOG
        self.capabilities = (capability_catalog or CapabilityCatalog()).load()
        self._agents: Dict[str, AgentDefinition] = {}
        self._loaded = False

    def load(self) -> "AgentRegistry":
        if self._loaded or yaml is None:
            self._loaded = True
            return self
        data = yaml.safe_load(self.catalog_path.read_text(encoding="utf-8")) or {}
        for a in data.get("agents", []):
            aid = a.get("id")
            if not aid:
                continue
            self._agents[aid] = AgentDefinition(
                agent_id=aid, priority=int(a.get("priority", 5)),
                allowed_categories=list(a.get("allowed_categories") or []),
                responsibilities=a.get("responsibilities", ""),
                expected_outputs=list(a.get("expected_outputs") or []),
                capability_scope=list(a.get("capability_scope") or []),
                knowledge_agent=bool(a.get("knowledge_agent", False)))
        self._loaded = True
        return self

    def all(self) -> List[AgentDefinition]:
        """Agents ordered deterministically: priority desc, then agent_id asc."""
        self.load()
        return sorted(self._agents.values(), key=lambda a: (-a.priority, a.agent_id))

    def get(self, agent_id: str) -> Optional[AgentDefinition]:
        self.load()
        return self._agents.get(agent_id)

    def count(self) -> int:
        return len(self.all())
