"""
SkillGraph (Phase R) — the skill dependency + composition graph.

Because the declarative `chain_to` field is unpopulated, skill DEPENDENCIES are DERIVED from the
capability dependency graph: a `requires`/`enhances` edge between two capabilities induces a directed
edge between the skills that own them (skill(a) → skill(b) when capability a requires/enhances b).
Skill COMPOSITION edges are induced by shared capabilities (undirected). Deterministic, read-only,
advisory; O(S + C + D) with the pairwise step bounded by skills-per-capability (a small constant).
"""

from __future__ import annotations

from typing import Dict, Optional, Set

from hydra.skill_intel.context import SkillContext


class SkillGraph:
    def __init__(self, cc: Optional[SkillContext] = None):
        self.cc = cc or SkillContext()
        self._built: Optional[Dict] = None

    def build(self) -> Dict:
        if self._built is not None:
            return self._built
        cap_to_skills = self.cc.cap_to_skills()
        nodes = sorted(self.cc.skills_by_id())
        dep: Set[tuple] = set()
        for e in self.cc.graph().edges():
            if e["relation"] not in ("requires", "enhances"):
                continue
            for sa in cap_to_skills.get(e["from"], []):
                for sb in cap_to_skills.get(e["to"], []):
                    if sa != sb:
                        dep.add((sa, sb, e["relation"]))
        dependency_edges = sorted(({"from": a, "to": b, "relation": r} for (a, b, r) in dep),
                                  key=lambda x: (x["relation"], x["from"], x["to"]))
        comp: Set[tuple] = set()
        for skills in cap_to_skills.values():
            for i in range(len(skills)):
                for j in range(i + 1, len(skills)):
                    comp.add((skills[i], skills[j]))
        composition_edges = sorted(({"from": a, "to": b, "relation": "shared_capability"}
                                    for (a, b) in comp), key=lambda x: (x["from"], x["to"]))
        self._built = {
            "nodes": nodes, "node_count": len(nodes),
            "dependency_edges": dependency_edges, "dependency_edge_count": len(dependency_edges),
            "composition_edges": composition_edges, "composition_edge_count": len(composition_edges),
            "advisory": True,
        }
        return self._built

    def dependency_adjacency(self) -> Dict[str, Set[str]]:
        adj: Dict[str, Set[str]] = {}
        for e in self.build()["dependency_edges"]:
            adj.setdefault(e["from"], set()).add(e["to"])
        return adj

    def composition_adjacency(self) -> Dict[str, Set[str]]:
        adj: Dict[str, Set[str]] = {}
        for e in self.build()["composition_edges"]:
            adj.setdefault(e["from"], set()).add(e["to"])
            adj.setdefault(e["to"], set()).add(e["from"])
        return adj
