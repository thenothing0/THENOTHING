"""General-purpose graph query engine — paths, filtering, components, centrality."""

from __future__ import annotations

import logging
from collections import deque
from typing import TYPE_CHECKING, Callable, Dict, List, Optional, Set, Tuple

from hydra.graph.models import Edge, EntityType, Node, RelationshipType

if TYPE_CHECKING:
    from hydra.graph.knowledge_graph import KnowledgeGraph

logger = logging.getLogger("hydra.graph.query")


class GraphQueryEngine:
    """Stateless query engine operating over a :class:`KnowledgeGraph`."""

    def __init__(self, graph: KnowledgeGraph) -> None:
        self._graph = graph

    # ── path queries ────────────────────────────────────────────

    def shortest_path(self, source: str, target: str) -> List[str]:
        """BFS shortest path (undirected). Returns [] if unreachable."""
        if source == target:
            return [source]
        if self._graph.get_node(source) is None or self._graph.get_node(target) is None:
            return []

        visited: Set[str] = {source}
        queue: deque[List[str]] = deque([[source]])
        while queue:
            path = queue.popleft()
            current = path[-1]
            for neighbor in self._graph.neighbors(current):
                if neighbor == target:
                    return path + [neighbor]
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(path + [neighbor])
        return []

    def all_shortest_paths(
        self, source: str, target: str, *, cap: int = 100,
    ) -> List[List[str]]:
        """All shortest paths (BFS, undirected), capped at *cap*."""
        if source == target:
            return [[source]]
        if self._graph.get_node(source) is None or self._graph.get_node(target) is None:
            return []

        results: List[List[str]] = []
        shortest_len: Optional[int] = None
        visited_at_depth: Dict[str, int] = {source: 0}
        queue: deque[List[str]] = deque([[source]])

        while queue:
            path = queue.popleft()
            depth = len(path)
            if shortest_len is not None and depth > shortest_len:
                break
            current = path[-1]
            for neighbor in self._graph.neighbors(current):
                new_depth = depth + 1
                if neighbor == target:
                    results.append(path + [neighbor])
                    shortest_len = new_depth
                    if len(results) >= cap:
                        return results
                elif neighbor not in visited_at_depth or visited_at_depth[neighbor] >= new_depth:
                    visited_at_depth[neighbor] = new_depth
                    queue.append(path + [neighbor])
        return results

    # ── neighborhood ────────────────────────────────────────────

    def k_hop_neighbors(self, node_id: str, k: int) -> Set[str]:
        """All nodes reachable within *k* hops (undirected)."""
        if k < 1 or self._graph.get_node(node_id) is None:
            return set()
        visited: Set[str] = {node_id}
        frontier: Set[str] = {node_id}
        for _ in range(k):
            next_frontier: Set[str] = set()
            for n in frontier:
                for nb in self._graph.neighbors(n):
                    if nb not in visited:
                        visited.add(nb)
                        next_frontier.add(nb)
            frontier = next_frontier
            if not frontier:
                break
        visited.discard(node_id)
        return visited

    def reachable(self, start: str, max_depth: int = 100) -> Set[str]:
        """Forward-reachable nodes (directed outgoing edges only)."""
        if self._graph.get_node(start) is None:
            return set()
        visited: Set[str] = set()
        queue: deque[Tuple[str, int]] = deque([(start, 0)])
        while queue:
            current, depth = queue.popleft()
            if current in visited:
                continue
            visited.add(current)
            if depth >= max_depth:
                continue
            for edge in self._graph.outgoing(current):
                if edge.target not in visited:
                    queue.append((edge.target, depth + 1))
        visited.discard(start)
        return visited

    def reverse_reachable(self, start: str, max_depth: int = 100) -> Set[str]:
        """Backward-reachable nodes (directed incoming edges only)."""
        if self._graph.get_node(start) is None:
            return set()
        visited: Set[str] = set()
        queue: deque[Tuple[str, int]] = deque([(start, 0)])
        while queue:
            current, depth = queue.popleft()
            if current in visited:
                continue
            visited.add(current)
            if depth >= max_depth:
                continue
            for edge in self._graph.incoming(current):
                if edge.source not in visited:
                    queue.append((edge.source, depth + 1))
        visited.discard(start)
        return visited

    # ── filtering ───────────────────────────────────────────────

    def filter_nodes(
        self,
        *,
        entity_type: Optional[EntityType] = None,
        min_confidence: float = 0.0,
        name_prefix: str = "",
        predicate: Optional[Callable[[Node], bool]] = None,
    ) -> List[Node]:
        """Filter nodes by type, confidence, name prefix, or arbitrary predicate."""
        nodes = self._graph.all_nodes()
        if entity_type is not None:
            nodes = [n for n in nodes if n.type == entity_type]
        if min_confidence > 0.0:
            nodes = [n for n in nodes if n.confidence >= min_confidence]
        if name_prefix:
            lp = name_prefix.lower()
            nodes = [n for n in nodes if n.name.lower().startswith(lp)]
        if predicate is not None:
            nodes = [n for n in nodes if predicate(n)]
        return nodes

    def filter_edges(
        self,
        *,
        relationship: Optional[RelationshipType] = None,
        min_confidence: float = 0.0,
        source_type: Optional[EntityType] = None,
        target_type: Optional[EntityType] = None,
    ) -> List[Edge]:
        """Filter edges by relationship, confidence, or endpoint types."""
        edges = self._graph.all_edges()
        if relationship is not None:
            edges = [e for e in edges if e.relationship == relationship]
        if min_confidence > 0.0:
            edges = [e for e in edges if e.confidence >= min_confidence]
        if source_type is not None:
            edges = [
                e for e in edges
                if (src := self._graph.get_node(e.source)) is not None and src.type == source_type
            ]
        if target_type is not None:
            edges = [
                e for e in edges
                if (tgt := self._graph.get_node(e.target)) is not None and tgt.type == target_type
            ]
        return edges

    # ── search ──────────────────────────────────────────────────

    def search(self, query: str, *, limit: int = 20) -> List[Node]:
        """Token-overlap search across node name + id + attributes."""
        tokens = set(query.lower().split())
        if not tokens:
            return []

        scored: List[Tuple[float, Node]] = []
        for node in self._graph.all_nodes():
            haystack = f"{node.id} {node.name} {' '.join(str(v) for v in node.attributes.values())}".lower()
            hay_tokens = set(haystack.split())
            overlap = len(tokens & hay_tokens)
            if overlap > 0:
                score = overlap / len(tokens)
                scored.append((score, node))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [node for _, node in scored[:limit]]

    # ── components & centrality ─────────────────────────────────

    def connected_components(self) -> List[Set[str]]:
        """Undirected connected components."""
        visited: Set[str] = set()
        components: List[Set[str]] = []
        for node in self._graph.all_nodes():
            if node.id in visited:
                continue
            component: Set[str] = set()
            queue: deque[str] = deque([node.id])
            while queue:
                current = queue.popleft()
                if current in visited:
                    continue
                visited.add(current)
                component.add(current)
                for nb in self._graph.neighbors(current):
                    if nb not in visited:
                        queue.append(nb)
            components.append(component)
        return components

    def centrality(self, method: str = "degree") -> Dict[str, float]:
        """Degree centrality (normalized). Only 'degree' is supported."""
        nodes = self._graph.all_nodes()
        n = len(nodes)
        if n <= 1:
            return {nd.id: 0.0 for nd in nodes}
        denom = n - 1
        return {
            nd.id: round(self._graph.degree(nd.id) / denom, 6)
            for nd in nodes
        }

    # ── subgraph ────────────────────────────────────────────────

    def subgraph(self, node_ids: Set[str]) -> Tuple[List[Node], List[Edge]]:
        """Extract the induced subgraph for *node_ids*."""
        nodes = [
            n for nid in node_ids
            if (n := self._graph.get_node(nid)) is not None
        ]
        edges = [
            e for e in self._graph.all_edges()
            if e.source in node_ids and e.target in node_ids
        ]
        return nodes, edges
