"""
SkillComposition (Phase R) — how skills compose.

Composition edges are induced by shared capabilities; composition clusters are the connected
components of the composition graph (coherent skill groups). Deterministic, read-only, advisory;
O(S + E).
"""

from __future__ import annotations

from typing import Dict, List, Optional

from hydra.skill_intel.context import SkillContext
from hydra.skill_intel.skill_graph import SkillGraph


class SkillComposition:
    def __init__(self, cc: Optional[SkillContext] = None, graph: Optional[SkillGraph] = None):
        self.cc = cc or SkillContext()
        self.graph = graph or SkillGraph(self.cc)

    def clusters(self) -> List[List[str]]:
        adj = self.graph.composition_adjacency()
        seen, out = set(), []
        for node in self.graph.build()["nodes"]:
            if node in seen:
                continue
            stack, comp = [node], set()
            while stack:
                x = stack.pop()
                if x in comp:
                    continue
                comp.add(x)
                seen.add(x)
                stack.extend(adj.get(x, set()) - comp)
            out.append(sorted(comp))
        out.sort(key=lambda c: (-len(c), c[0]))
        return out

    def report(self) -> Dict:
        g = self.graph.build()
        clusters = self.clusters()
        return {"composition_edges": g["composition_edges"],
                "composition_edge_count": g["composition_edge_count"],
                "composition_clusters": [{"skills": c, "size": len(c)} for c in clusters],
                "cluster_count": len(clusters), "advisory": True}
