"""
OpportunityGraph (Phase S) — the structure that links capabilities to what they unlock.

A bipartite capability ↔ finding-type graph ("addresses" edges) overlaid with the capability
dependency edges (requires/enhances). It surfaces the STRUCTURE of opportunity:
  * bottleneck finding-types  — addressable by only one/few capabilities (fragile coverage);
  * hub capabilities          — cover many finding-types and/or sit central in the dep graph;
  * unique finding-types per capability — finding-types it is the SOLE capability for (max leverage).
Bounded, deterministic, read-only, advisory; O(C + F + D). NON-executing — it scores the MODEL.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from hydra.opportunity_intel.context import OpportunityContext
from hydra.opportunity_intel.util import norm


class OpportunityGraph:
    def __init__(self, oc: Optional[OpportunityContext] = None):
        self.oc = oc or OpportunityContext()
        self._built: Optional[Dict] = None

    def build(self) -> Dict:
        if self._built is not None:
            return self._built
        cat = self.oc.catalog()
        caps = cat.all()
        ft_to_caps: Dict[str, List[str]] = {}
        addresses: List[Dict] = []
        for c in caps:
            for ft in sorted(c.supported_finding_types):
                ft_to_caps.setdefault(ft, []).append(c.capability_id)
                addresses.append({"capability": c.capability_id, "finding_type": ft})
        for ft in ft_to_caps:
            ft_to_caps[ft] = sorted(set(ft_to_caps[ft]))
        addresses.sort(key=lambda e: (e["capability"], e["finding_type"]))

        # capability dependency edges (requires/enhances), degree per capability
        dep_edges: List[Dict] = []
        degree: Dict[str, int] = {}
        for e in self.oc.graph().edges():
            if e["relation"] in ("requires", "enhances"):
                dep_edges.append({"from": e["from"], "to": e["to"], "relation": e["relation"]})
                degree[e["from"]] = degree.get(e["from"], 0) + 1
                degree[e["to"]] = degree.get(e["to"], 0) + 1
        dep_edges.sort(key=lambda e: (e["relation"], e["from"], e["to"]))
        max_degree = max(degree.values(), default=1) or 1

        # per-capability leverage: finding-types it is the SOLE provider for
        unique_ft: Dict[str, List[str]] = {}
        for ft, providers in ft_to_caps.items():
            if len(providers) == 1:
                unique_ft.setdefault(providers[0], []).append(ft)

        hub_rows = []
        for c in caps:
            cid = c.capability_id
            ft_degree = len(c.supported_finding_types)
            hub_rows.append({
                "capability_id": cid, "category": c.category,
                "finding_type_degree": ft_degree,
                "dependency_degree": degree.get(cid, 0),
                "unique_finding_types": sorted(unique_ft.get(cid, [])),
                "unique_finding_type_count": len(unique_ft.get(cid, [])),
                "leverage": round(0.6 * norm(ft_degree, max((len(x.supported_finding_types)
                                  for x in caps), default=1) or 1)
                                  + 0.4 * norm(degree.get(cid, 0), max_degree), 4),
            })
        hub_rows.sort(key=lambda d: (-d["leverage"], -d["unique_finding_type_count"],
                                     d["capability_id"]))

        bottlenecks = sorted(
            ({"finding_type": ft, "capabilities": providers, "provider_count": len(providers)}
             for ft, providers in ft_to_caps.items() if len(providers) <= 1),
            key=lambda d: (d["provider_count"], d["finding_type"]))

        self._built = {
            "capability_nodes": len(caps),
            "finding_type_nodes": len(ft_to_caps),
            "addresses_edges": addresses, "addresses_edge_count": len(addresses),
            "dependency_edges": dep_edges, "dependency_edge_count": len(dep_edges),
            "hub_capabilities": hub_rows[:10],
            "bottleneck_finding_types": bottlenecks[:15],
            "bottleneck_count": len(bottlenecks),
            "advisory": True,
        }
        return self._built

    def report(self) -> Dict:
        return self.build()
