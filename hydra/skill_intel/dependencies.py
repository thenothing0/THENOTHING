"""
SkillDependencyAnalyzer (Phase R) — skill dependency intelligence.

Over the derived skill dependency graph: dependency edges, critical skills (most depended-upon),
isolated skills, directed cycles, dependency paths. Deterministic, read-only, advisory; O(S + E).
"""

from __future__ import annotations

from typing import Dict, List, Optional

from hydra.skill_intel.context import SkillContext
from hydra.skill_intel.skill_graph import SkillGraph


class SkillDependencyAnalyzer:
    def __init__(self, cc: Optional[SkillContext] = None, graph: Optional[SkillGraph] = None):
        self.cc = cc or SkillContext()
        self.graph = graph or SkillGraph(self.cc)

    def critical_skills(self, top: int = 10) -> List[Dict]:
        indeg: Dict[str, int] = {}
        for src, tos in self.graph.dependency_adjacency().items():
            for t in tos:
                indeg[t] = indeg.get(t, 0) + 1
        rows = sorted(({"skill_id": k, "dependents": v} for k, v in indeg.items()),
                      key=lambda d: (-d["dependents"], d["skill_id"]))
        return rows[:max(1, top)]

    def isolated_skills(self) -> List[str]:
        g = self.graph.build()
        connected = set()
        for e in g["dependency_edges"] + g["composition_edges"]:
            connected.add(e["from"])
            connected.add(e["to"])
        return sorted(s for s in g["nodes"] if s not in connected)

    def cycles(self) -> List[List[str]]:
        adj = self.graph.dependency_adjacency()
        WHITE, GRAY, BLACK = 0, 1, 2
        color: Dict[str, int] = {}
        cycles: List[List[str]] = []

        def dfs(node: str, stack: List[str]) -> None:
            color[node] = GRAY
            stack.append(node)
            for nb in sorted(adj.get(node, ())):
                if color.get(nb, WHITE) == GRAY:
                    cycles.append(stack[stack.index(nb):] + [nb])
                elif color.get(nb, WHITE) == WHITE:
                    dfs(nb, stack)
            stack.pop()
            color[node] = BLACK

        for n in sorted(set(adj) | {x for v in adj.values() for x in v}):
            if color.get(n, WHITE) == WHITE:
                dfs(n, [])
        return [list(c) for c in sorted({tuple(c) for c in cycles})]

    def report(self) -> Dict:
        g = self.graph.build()
        cyc = self.cycles()
        return {"dependency_edges": g["dependency_edges"],
                "dependency_edge_count": g["dependency_edge_count"],
                "critical_skills": self.critical_skills(),
                "isolated_skills": self.isolated_skills(),
                "isolated_count": len(self.isolated_skills()),
                "cycles": cyc, "acyclic": not cyc, "advisory": True}
