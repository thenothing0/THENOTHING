"""
CapabilityDependencyGraph + DependencyIntelligence (Phase M).

A deterministic, read-only dependency graph over capabilities. Edges are declarative
(`requires` | `enhances` | `related_to`) merged from a core data file
(`capabilities/capability_dependencies.yaml`) and the enabled plugins. Provides cycle
detection, dependency paths, critical/isolated capabilities, and coverage gaps.

Pure / read-only: no execution, no canonical writes; promotion.py / confidence.py untouched.
Complexity O(C + D): single passes over capabilities + dependency edges; BFS for paths.
"""

from __future__ import annotations

from collections import defaultdict, deque
from pathlib import Path
from typing import Dict, List, Optional

from hydra.capabilities.capability_catalog import CapabilityCatalog

try:
    import yaml
except Exception:  # pragma: no cover
    yaml = None

_CORE_DEPS = Path(__file__).resolve().parents[2] / "capabilities" / "capability_dependencies.yaml"
RELATIONS = ("requires", "enhances", "related_to")
# Relations that imply a directed prerequisite ordering (used for paths + cycle detection).
_DIRECTED = ("requires", "enhances")


class CapabilityDependencyGraph:
    def __init__(self, catalog: Optional[CapabilityCatalog] = None,
                 plugin_edges: Optional[List[Dict]] = None,
                 core_deps_path: Optional[Path | str] = None):
        self.catalog = (catalog or CapabilityCatalog()).load()
        self.core_deps_path = Path(core_deps_path) if core_deps_path else _CORE_DEPS
        self._edges: List[Dict] = []
        self._plugin_edges = plugin_edges or []
        self._loaded = False
        # adjacency by relation: rel → {from → [to]} and reverse for in-degree
        self._adj: Dict[str, Dict[str, List[str]]] = {r: defaultdict(list) for r in RELATIONS}
        self._radj: Dict[str, Dict[str, List[str]]] = {r: defaultdict(list) for r in RELATIONS}

    def load(self) -> "CapabilityDependencyGraph":
        if self._loaded:
            return self
        core_edges: List[Dict] = []
        if yaml is not None and self.core_deps_path.exists():
            data = yaml.safe_load(self.core_deps_path.read_text(encoding="utf-8")) or {}
            core_edges = list(data.get("dependencies") or [])
        # deterministic, de-duplicated edge set
        seen = set()
        for e in core_edges + list(self._plugin_edges):
            rel, a, b = e.get("relation"), e.get("from"), e.get("to")
            if rel not in RELATIONS or not a or not b:
                continue
            key = (rel, a, b)
            if key in seen:
                continue
            seen.add(key)
            self._edges.append({"relation": rel, "from": a, "to": b})
            self._adj[rel][a].append(b)
            self._radj[rel][b].append(a)
        self._loaded = True
        return self

    # ── queries ──────────────────────────────────────────────────────────────────
    def edges(self) -> List[Dict]:
        self.load()
        return sorted(self._edges, key=lambda e: (e["relation"], e["from"], e["to"]))

    def neighbors(self, capability_id: str, relation: str = "requires") -> List[str]:
        self.load()
        return sorted(self._adj.get(relation, {}).get(capability_id, []))

    def detect_cycles(self, relation: str = "requires") -> List[List[str]]:
        """Detect directed cycles in a relation (requires must be acyclic). Deterministic."""
        self.load()
        adj = self._adj.get(relation, {})
        WHITE, GRAY, BLACK = 0, 1, 2
        color: Dict[str, int] = defaultdict(int)
        cycles: List[List[str]] = []

        def dfs(node: str, stack: List[str]):
            color[node] = GRAY
            stack.append(node)
            for nb in sorted(adj.get(node, [])):
                if color[nb] == GRAY:
                    cycles.append(stack[stack.index(nb):] + [nb])
                elif color[nb] == WHITE:
                    dfs(nb, stack)
            stack.pop()
            color[node] = BLACK

        for n in sorted({k for k in adj} | {x for v in adj.values() for x in v}):
            if color[n] == WHITE:
                dfs(n, [])
        # de-dup cycles deterministically
        uniq = sorted({tuple(c) for c in cycles})
        return [list(c) for c in uniq]

    def dependency_paths(self, src: str, dst: str) -> List[str]:
        """Shortest directed path src→dst over requires+enhances (BFS). [] if none."""
        self.load()
        if src == dst:
            return [src]
        q = deque([[src]])
        seen = {src}
        while q:
            path = q.popleft()
            node = path[-1]
            nexts = sorted({nb for rel in _DIRECTED for nb in self._adj[rel].get(node, [])})
            for nb in nexts:
                if nb == dst:
                    return path + [nb]
                if nb not in seen:
                    seen.add(nb)
                    q.append(path + [nb])
        return []

    def critical_capabilities(self, top: int = 10) -> List[Dict]:
        """Most-depended-upon capabilities (highest `requires` in-degree)."""
        self.load()
        scored = [{"capability_id": cid, "dependents": len(set(srcs))}
                  for cid, srcs in self._radj["requires"].items()]
        scored.sort(key=lambda d: (-d["dependents"], d["capability_id"]))
        return scored[: max(1, top)]

    def isolated_capabilities(self) -> List[str]:
        """Capabilities with no dependency edge of any relation (advisory)."""
        self.load()
        connected = set()
        for rel in RELATIONS:
            connected |= set(self._adj[rel]) | set(self._radj[rel])
        return sorted(c.capability_id for c in self.catalog.all()
                      if c.capability_id not in connected)

    def coverage_gaps(self) -> List[str]:
        """Edge endpoints referenced but absent from the effective catalog."""
        self.load()
        known = {c.capability_id for c in self.catalog.all()}
        refs = {e["from"] for e in self._edges} | {e["to"] for e in self._edges}
        return sorted(refs - known)


class DependencyIntelligence:
    """Read-only dependency analytics over the effective catalog + graph."""

    def __init__(self, graph: Optional[CapabilityDependencyGraph] = None):
        self.graph = (graph or CapabilityDependencyGraph()).load()

    def report(self) -> Dict:
        cycles = self.graph.detect_cycles("requires")
        by_rel: Dict[str, int] = {}
        for e in self.graph.edges():
            by_rel[e["relation"]] = by_rel.get(e["relation"], 0) + 1
        return {
            "edge_count": len(self.graph.edges()),
            "edges_by_relation": dict(sorted(by_rel.items())),
            "requires_acyclic": not cycles,
            "cycles": cycles,
            "critical_capabilities": self.graph.critical_capabilities(),
            "isolated_capabilities": self.graph.isolated_capabilities(),
            "isolated_count": len(self.graph.isolated_capabilities()),
            "coverage_gaps": self.graph.coverage_gaps(),
        }
