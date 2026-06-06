"""
FederationMarketplace (Phase N) — advisory ecosystem discovery.

Compares the federation-wide intelligence (IntelligenceMesh) against the LOCAL effective
catalog to surface opportunities: capabilities popular elsewhere but missing locally, the
most widely-adopted plugins, and locally underrepresented categories.

ADVISORY ONLY. It recommends; it NEVER installs, executes, downloads, or mutates anything —
and it never touches promotion / confidence / wiki. Deterministic, read-only, O(E).
"""

from __future__ import annotations

from typing import Dict, List, Optional

from hydra.federation.intelligence import IntelligenceMesh
from hydra.federation.store import KnowledgeExchangeStore


class FederationMarketplace:
    def __init__(self, store: Optional[KnowledgeExchangeStore] = None,
                 mesh: Optional[IntelligenceMesh] = None, local_catalog=None):
        self.store = store or (mesh.store if mesh else KnowledgeExchangeStore())
        self.mesh = mesh or IntelligenceMesh(self.store)
        self._local_catalog = local_catalog

    def _local(self):
        if self._local_catalog is None:
            from hydra.plugins.plugin_catalog import EffectiveCapabilityCatalog
            self._local_catalog = EffectiveCapabilityCatalog().load()
        return self._local_catalog

    def _local_ids(self) -> set:
        return {c.capability_id for c in self._local().all()}

    def _local_category_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for c in self._local().all():
            counts[c.category] = counts.get(c.category, 0) + 1
        return counts

    # ── advisory views ───────────────────────────────────────────────────────────
    def missing_capabilities(self, min_peers: int = 2) -> List[Dict]:
        """Capabilities the federation exercises (≥min_peers) but the local node lacks."""
        local = self._local_ids()
        out = [{"capability_id": p["capability_id"], "category": p["category"],
                "peer_count": p["peer_count"], "mean_effectiveness": p["mean_effectiveness"]}
               for p in self.mesh.capability_popularity()
               if p["capability_id"] not in local and p["peer_count"] >= min_peers]
        out.sort(key=lambda d: (-d["peer_count"], -d["mean_effectiveness"], d["capability_id"]))
        return out

    def popular_plugins(self, min_peers: int = 1) -> List[Dict]:
        try:
            from hydra.plugins.plugin_registry import PluginRegistry
            installed = {p.plugin_id for p in PluginRegistry().enabled_plugins()}
        except Exception:
            installed = set()
        out = []
        for row in self.mesh.plugin_adoption_trends():
            if row["adopting_peers"] >= min_peers:
                out.append({**row, "installed_locally": row["plugin_id"] in installed})
        return out

    def underrepresented_categories(self) -> List[Dict]:
        """Categories present federation-wide that are weak/absent locally."""
        local_counts = self._local_category_counts()
        mean_local = (sum(local_counts.values()) / len(local_counts)) if local_counts else 0.0
        out = []
        for row in self.mesh.source_category_trends():
            cat = row["source_category"]
            local_n = local_counts.get(cat, 0)
            if local_n < max(1, mean_local * 0.5):
                out.append({"category": cat, "local_capabilities": local_n,
                            "federation_mean_effectiveness": row["mean_effectiveness"],
                            "federation_peer_count": row["peer_count"]})
        out.sort(key=lambda d: (d["local_capabilities"], -d["federation_mean_effectiveness"],
                                d["category"]))
        return out

    def ecosystem_opportunities(self) -> Dict:
        missing = self.missing_capabilities()
        plugins = self.popular_plugins()
        under = self.underrepresented_categories()
        not_installed = [p for p in plugins if not p["installed_locally"]]
        recommendations = (
            [f"adopt capability '{m['capability_id']}' (used by {m['peer_count']} peers)"
             for m in missing[:5]] +
            [f"consider plugin '{p['plugin_id']}' (adopted by {p['adopting_peers']} peers)"
             for p in not_installed[:5]] +
            [f"grow coverage in '{u['category']}' (only {u['local_capabilities']} local caps)"
             for u in under[:5]])
        return {
            "missing_capabilities": missing,
            "popular_plugins": plugins,
            "underrepresented_categories": under,
            "recommendations": recommendations,
            "advisory": True,
            "note": "discovery only — nothing is installed, executed, or written",
        }
