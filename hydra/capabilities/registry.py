"""
Capability registry — capability-first reconnaissance.

THENOTHING reasons in terms of CAPABILITIES (discover_subdomains, http_probe,
dns_intelligence, ...), never specific tools. Each capability declares its
sources, confidence rules and I/O in a YAML spec under `capabilities/`. The
planner/fusion select sources by capability + execution policy; swapping tools
never changes the plan.

Mirrors the data-first loader pattern of `hydra/skills/yaml_loader.py`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

try:
    import yaml
except Exception:  # pragma: no cover
    yaml = None

from hydra.capabilities.sources import ExecutionPolicy, Source

logger = logging.getLogger("hydra.capabilities.registry")

# repo-root/capabilities  (this file: hydra/capabilities/registry.py)
_DEFAULT_ROOT = Path(__file__).resolve().parents[2] / "capabilities"


@dataclass
class Capability:
    name: str
    description: str = ""
    inputs: List[str] = field(default_factory=list)
    outputs: List[str] = field(default_factory=list)
    sources: List[Source] = field(default_factory=list)
    confidence_rules: Dict[str, List[str]] = field(default_factory=dict)

    def source_weights(self) -> Dict[str, float]:
        """{source_id: confidence_weight} — keyed on the stable id."""
        return {s.id: s.confidence_weight for s in self.sources}

    def runnable_sources(self, policy: ExecutionPolicy) -> List[Source]:
        return [s for s in self.sources if s.runnable(policy)]

    def to_dict(self) -> Dict:
        return {
            "capability": self.name,
            "description": self.description,
            "inputs": self.inputs,
            "outputs": self.outputs,
            "sources": [s.to_dict() for s in self.sources],
            "confidence_rules": self.confidence_rules,
        }


class CapabilityRegistry:
    def __init__(self, root: Optional[Path | str] = None):
        self.root = Path(root) if root else _DEFAULT_ROOT
        self._caps: Dict[str, Capability] = {}
        self._loaded = False

    def load(self) -> "CapabilityRegistry":
        if self._loaded:
            return self
        if yaml is None:  # pragma: no cover
            self._loaded = True
            return self
        for path in sorted(self.root.glob("*.yaml")):
            try:
                cap = self._parse(yaml.safe_load(path.read_text(encoding="utf-8")) or {})
                if cap:
                    self._caps[cap.name] = cap
            except Exception as e:  # pragma: no cover - defensive
                logger.warning(f"failed to load capability {path.name}: {e}")
        self._loaded = True
        logger.info(f"🧩 capability registry: {len(self._caps)} capabilities loaded")
        return self

    @staticmethod
    def _parse(data: Dict) -> Optional[Capability]:
        name = data.get("capability")
        if not name:
            return None
        sources = [Source.from_dict(s) for s in (data.get("sources") or [])]
        return Capability(
            name=name,
            description=data.get("description", ""),
            inputs=list(data.get("inputs") or []),
            outputs=list(data.get("outputs") or []),
            sources=sources,
            confidence_rules=dict(data.get("confidence_rules") or {}),
        )

    # ── access ───────────────────────────────────────────────────────────
    def names(self) -> List[str]:
        self.load()
        return sorted(self._caps)

    def get(self, name: str) -> Optional[Capability]:
        self.load()
        return self._caps.get(name)

    def select(self, name: str, policy: Optional[ExecutionPolicy] = None) -> List[Source]:
        """Return the sources for a capability that are runnable under the policy."""
        cap = self.get(name)
        if not cap:
            raise KeyError(f"unknown capability: {name}")
        return cap.runnable_sources(policy or ExecutionPolicy.offline())

    def all(self) -> Dict[str, Capability]:
        self.load()
        return dict(self._caps)
