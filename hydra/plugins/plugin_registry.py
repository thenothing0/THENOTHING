"""
PluginRegistry (Phase M) — declarative plugin lifecycle + effective-catalog composition.

Discovers/validates plugins, tracks the enabled set, and exposes the union of plugin
capabilities + dependency edges that compose (with the core catalog) into the EFFECTIVE
capability ecosystem. Capability ids stay globally unique — duplicates are rejected.

Read-only over data; deterministic (sorted by plugin_id). No execution, no network, no
canonical writes; promotion.py / confidence.py untouched.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from hydra.capabilities.capability_catalog import CapabilityCatalog
from hydra.plugins.plugin_loader import PluginLoader
from hydra.plugins.plugin_validator import PluginDefinition, PluginValidator


class PluginRegistry:
    def __init__(self, loader: Optional[PluginLoader] = None,
                 core_catalog: Optional[CapabilityCatalog] = None,
                 auto_discover: bool = True):
        self.loader = loader or PluginLoader()
        self.core = (core_catalog or CapabilityCatalog()).load()
        self.validator = PluginValidator()
        self._core_ids = {c.capability_id for c in self.core.all()}
        self._available: Dict[str, PluginDefinition] = {}
        self._enabled: set = set()
        self._errors: Dict[str, List[str]] = {}
        # Incrementally-maintained effective id set (core + enabled plugin caps). Keeping
        # it incremental makes plugin loading O(C) total, not O(P²) (no per-plugin rescan).
        self._eff_ids: set = set(self._core_ids)
        self._loaded = False
        self._auto = auto_discover

    # ── lifecycle ────────────────────────────────────────────────────────────────
    def _ensure(self) -> "PluginRegistry":
        if self._loaded:
            return self
        self._loaded = True
        if self._auto:
            for pd in self.loader.discover():          # sorted by plugin_id
                self._ingest(pd, enable_if_valid=True)
        return self

    def _ingest(self, pd: PluginDefinition, enable_if_valid: bool) -> List[str]:
        """Validate against the CURRENT effective ids and record. Enables only if clean.
        O(caps) — checks the incrementally-maintained id set, no per-plugin rescan."""
        errors = self.validator.validate(pd, existing_capability_ids=self._eff_ids)
        errors += self.validator.check_version_compat(
            pd, {pid: self._available[pid].version for pid in self._enabled})
        self._available[pd.plugin_id] = pd
        self._errors[pd.plugin_id] = errors
        if enable_if_valid and not errors:
            self._enabled.add(pd.plugin_id)
            self._eff_ids |= set(pd.capability_ids)
        return errors

    def register_plugin(self, pd: PluginDefinition) -> List[str]:
        """Register (and enable if valid) a plugin. Returns validation errors."""
        self._ensure()
        return self._ingest(pd, enable_if_valid=True)

    def load_plugin(self, plugin_id: str) -> List[str]:
        """Enable an available plugin (re-validates against the current effective ids)."""
        self._ensure()
        pd = self._available.get(plugin_id)
        if pd is None:
            return [f"unknown plugin: {plugin_id}"]
        if plugin_id in self._enabled:
            return []
        errors = self.validator.validate(pd, existing_capability_ids=self._eff_ids)
        if errors:
            self._errors[plugin_id] = errors
            return errors
        self._enabled.add(plugin_id)
        self._eff_ids |= set(pd.capability_ids)
        return []

    def unload_plugin(self, plugin_id: str) -> bool:
        self._ensure()
        if plugin_id in self._enabled:
            self._enabled.discard(plugin_id)
            self._eff_ids -= set(self._available[plugin_id].capability_ids)
            return True
        return False

    def validate_plugin(self, pd: PluginDefinition) -> List[str]:
        self._ensure()
        return self.validator.validate(pd, existing_capability_ids=self._eff_ids)

    # ── queries (deterministic) ──────────────────────────────────────────────────
    def _effective_ids(self) -> set:
        return set(self._eff_ids)

    def enabled_plugins(self) -> List[PluginDefinition]:
        self._ensure()
        return [self._available[p] for p in sorted(self._enabled)]

    def available_plugins(self) -> List[PluginDefinition]:
        self._ensure()
        return [self._available[p] for p in sorted(self._available)]

    def get_plugin(self, plugin_id: str) -> Optional[PluginDefinition]:
        self._ensure()
        return self._available.get(plugin_id)

    def errors_for(self, plugin_id: str) -> List[str]:
        self._ensure()
        return self._errors.get(plugin_id, [])

    def list_plugins(self) -> List[Dict]:
        self._ensure()
        out = []
        for pid in sorted(self._available):
            pd = self._available[pid]
            d = pd.to_dict()
            d["enabled"] = pid in self._enabled
            d["errors"] = self._errors.get(pid, [])
            out.append(d)
        return out

    def plugin_capabilities(self) -> List[Dict]:
        """Capability dicts contributed by enabled plugins (deterministic)."""
        out: List[Dict] = []
        for pd in self.enabled_plugins():
            for c in pd.capabilities:
                out.append({**c, "_plugin": pd.plugin_id})
        return out

    def plugin_dependency_edges(self) -> List[Dict]:
        edges: List[Dict] = []
        for pd in self.enabled_plugins():
            for e in pd.dependencies:
                edges.append({**e, "_plugin": pd.plugin_id})
        return edges

    def capability_owner_plugin(self) -> Dict[str, str]:
        return {c["id"]: c["_plugin"] for c in self.plugin_capabilities() if c.get("id")}
