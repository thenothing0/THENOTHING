"""
EcosystemAnalyzer + CapabilityMarketplace (Phase M).

Read-only ecosystem intelligence over the plugin registry + effective catalog + adapter
registry. EcosystemAnalyzer reports what plugins add (capabilities/adapters/agents/coverage);
CapabilityMarketplace advises on missing plugins, weak areas, underrepresented categories and
ecosystem gaps. Advisory only — never installs, executes, or writes the wiki.
"""

from __future__ import annotations

from typing import Dict, Optional

from hydra.adapters.adapter_registry import AdapterRegistry
from hydra.plugins.plugin_catalog import EffectiveCapabilityCatalog
from hydra.plugins.plugin_registry import PluginRegistry

# Capability categories the ecosystem is expected to cover well (for gap advice).
_EXPECTED_CATEGORIES = ("reconnaissance", "web", "api", "cloud", "source_code",
                        "secrets", "mobile", "infrastructure", "verification")


class _EcosystemBase:
    def __init__(self, registry: Optional[PluginRegistry] = None,
                 catalog: Optional[EffectiveCapabilityCatalog] = None,
                 adapters: Optional[AdapterRegistry] = None):
        self.registry = registry or PluginRegistry()
        self.catalog = (catalog or EffectiveCapabilityCatalog(self.registry)).load()
        self.adapters = (adapters or AdapterRegistry(catalog=self.catalog)).load()
        self._plugin_cap_ids = set(self.catalog.plugin_capability_ids())


class EcosystemAnalyzer(_EcosystemBase):
    def report(self) -> Dict:
        enabled = self.registry.enabled_plugins()
        adapters_added = sum(1 for a in self.adapters.all_adapters()
                             if a.capability_id in self._plugin_cap_ids)
        per_plugin = []
        for pd in enabled:
            cap_ids = set(pd.capability_ids)
            p_adapters = sum(1 for a in self.adapters.all_adapters() if a.capability_id in cap_ids)
            per_plugin.append({
                "plugin_id": pd.plugin_id, "version": pd.version,
                "capabilities_added": len(pd.capabilities), "adapters_added": p_adapters,
                "agents_added": len(pd.agents), "verification_coverage": pd.verification_coverage,
            })
        per_plugin.sort(key=lambda d: d["plugin_id"])
        comp = self.catalog.composition()
        return {
            "installed_plugins": len(enabled),
            "plugin_ids": sorted(p.plugin_id for p in enabled),
            "capabilities_added": comp["plugin"],
            "adapters_added": adapters_added,
            "agents_added": sum(len(p.agents) for p in enabled),
            "coverage_added": sum(p.verification_coverage for p in enabled),
            "effective_catalog": comp,
            "total_adapters": self.adapters.count(),
            "per_plugin": per_plugin,
        }


class CapabilityMarketplace(_EcosystemBase):
    def recommend(self) -> Dict:
        caps = self.catalog.all()
        by_cat: Dict[str, int] = {}
        for c in caps:
            by_cat[c.category] = by_cat.get(c.category, 0) + 1
        mean = sum(by_cat.values()) / len(by_cat) if by_cat else 0.0

        weak_areas = sorted(({"category": k, "capabilities": v}
                             for k, v in by_cat.items() if v < mean),
                            key=lambda d: (d["capabilities"], d["category"]))
        underrepresented = sorted(k for k, v in by_cat.items() if v < max(1, mean * 0.5))
        missing_categories = sorted(c for c in _EXPECTED_CATEGORIES if c not in by_cat)

        enabled = {p.plugin_id for p in self.registry.enabled_plugins()}
        missing_plugins = sorted(p.plugin_id for p in self.registry.available_plugins()
                                 if p.plugin_id not in enabled)

        ecosystem_gaps = missing_categories + [f"low coverage: {w['category']}" for w in weak_areas[:3]]
        return {
            "missing_plugins": missing_plugins,
            "weak_areas": weak_areas,
            "underrepresented_categories": underrepresented,
            "ecosystem_gaps": ecosystem_gaps,
            "category_distribution": dict(sorted(by_cat.items())),
            "mean_capabilities_per_category": round(mean, 2),
        }
