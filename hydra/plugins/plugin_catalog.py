"""
EffectiveCapabilityCatalog (Phase M) — core + plugin capabilities, composed.

A drop-in CapabilityCatalog (so AdapterRegistry / AgentRegistry / planners / simulators can
consume it unchanged) whose capability set is the UNION of the core catalog and the enabled
plugins' capabilities. Capability ids are globally unique; duplicates are rejected (skipped +
recorded) so there is always a single canonical capability per id.

Read-only; deterministic (sorted). The CORE catalog file is never modified.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional

from hydra.capabilities.capability_catalog import CapabilityCatalog, CapabilityEntry
from hydra.plugins.plugin_registry import PluginRegistry


class EffectiveCapabilityCatalog(CapabilityCatalog):
    def __init__(self, registry: Optional[PluginRegistry] = None,
                 catalog_path: Optional[Path | str] = None):
        super().__init__(catalog_path)
        self.registry = registry or PluginRegistry()
        self.rejected_duplicates: List[str] = []
        self._eff_loaded = False

    def load(self) -> "EffectiveCapabilityCatalog":
        if self._eff_loaded:
            return self
        super().load()                      # core capabilities into self._caps
        for c in self.registry.plugin_capabilities():
            cid = c.get("id")
            if not cid:
                continue
            if cid in self._caps:
                self.rejected_duplicates.append(cid)    # globally-unique id already present
                continue
            self._caps[cid] = CapabilityEntry(
                capability_id=cid, category=c.get("category", "reconnaissance"),
                supported_target_types=list(c.get("target_types") or []),
                supported_finding_types=list(c.get("finding_types") or []),
                verification_coverage=int(c.get("verification_coverage", 0) or 0),
                offline_runnable=bool(c.get("offline_runnable", False)),
                confidence_weight=float(c.get("confidence_weight", 0.4)),
                tools=list(c.get("tools") or []))
        self._eff_loaded = True
        return self

    def plugin_capability_ids(self) -> List[str]:
        self.load()
        return sorted(c["id"] for c in self.registry.plugin_capabilities()
                      if c.get("id") and c["id"] not in self.rejected_duplicates)

    def composition(self) -> Dict[str, int]:
        self.load()
        plugin_ids = set(self.plugin_capability_ids())
        return {"effective": self.count(),
                "core": self.count() - len(plugin_ids),
                "plugin": len(plugin_ids),
                "rejected_duplicates": len(self.rejected_duplicates)}
