"""Unified knowledge graph facade — thread-safe, indexed, serializable."""

from __future__ import annotations

import logging
import threading
from collections import deque
from pathlib import Path
from typing import Dict, List, Optional, Set, TYPE_CHECKING

from hydra.graph.graph_index import GraphIndex
from hydra.graph.graph_store import GraphStore
from hydra.graph.models import Edge, EntityType, GraphStats, Node, RelationshipType
from hydra.graph.serialization import GraphSerializer

if TYPE_CHECKING:
    from hydra.graph.normalizer import EntityNormalizer

logger = logging.getLogger("hydra.graph.knowledge_graph")

_UNSET = object()


class KnowledgeGraph:
    """
    Thread-safe knowledge graph combining GraphStore + GraphIndex.

    All mutations acquire an RLock so the graph can be safely shared
    across threads.  Read-only helpers also acquire the lock for
    snapshot consistency.

    If *normalize* is True (the default), node IDs are canonicalized
    on insert via :class:`EntityNormalizer`.
    """

    def __init__(self, *, normalize: bool = True) -> None:
        self._store = GraphStore()
        self._index = GraphIndex()
        self._lock = threading.RLock()
        self._normalizer: Optional[EntityNormalizer] = None
        if normalize:
            from hydra.graph.normalizer import EntityNormalizer
            self._normalizer = EntityNormalizer()

    # ── mutations ────────────────────────────────────────────

    def add_node(self, node: Node) -> bool:
        with self._lock:
            if self._normalizer is not None:
                node.id = self._normalizer.normalize_id(node.type, node.id)
            is_new = self._store.add_node(node)
            self._index.index_node(node)
            return is_new

    def add_edge(self, edge: Edge) -> bool:
        with self._lock:
            if self._normalizer is not None:
                src_node = self._store.get_node(edge.source)
                tgt_node = self._store.get_node(edge.target)
                if src_node is None or tgt_node is None:
                    norm_src = edge.source
                    norm_tgt = edge.target
                    for n in self._store.all_nodes():
                        if self._normalizer.normalize_id(n.type, edge.source) == n.id:
                            norm_src = n.id
                        if self._normalizer.normalize_id(n.type, edge.target) == n.id:
                            norm_tgt = n.id
                    edge.source = norm_src
                    edge.target = norm_tgt
            is_new = self._store.add_edge(edge)
            if is_new:
                self._index.index_edge(
                    edge.source, edge.target, edge.relationship,
                )
            return is_new

    def remove_node(self, node_id: str) -> bool:
        with self._lock:
            node = self._store.get_node(node_id)
            if node is None:
                return False
            for edge in list(self._store.outgoing(node_id)):
                self._index.remove_edge(
                    edge.source, edge.target, edge.relationship,
                )
            for edge in list(self._store.incoming(node_id)):
                self._index.remove_edge(
                    edge.source, edge.target, edge.relationship,
                )
            self._index.remove_node(node)
            return self._store.remove_node(node_id)

    def remove_edge(
        self, source: str, target: str, relationship: str,
    ) -> bool:
        with self._lock:
            try:
                rel = RelationshipType(relationship)
            except ValueError:
                return False
            self._index.remove_edge(source, target, rel)
            return self._store.remove_edge(source, target, relationship)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()
            self._index.clear()

    # ── read-only queries ────────────────────────────────────

    def get_node(self, node_id: str) -> Optional[Node]:
        with self._lock:
            return self._store.get_node(node_id)

    def neighbors(self, node_id: str) -> List[str]:
        with self._lock:
            return self._store.neighbors(node_id)

    def outgoing(self, node_id: str) -> List[Edge]:
        with self._lock:
            return list(self._store.outgoing(node_id))

    def incoming(self, node_id: str) -> List[Edge]:
        with self._lock:
            return list(self._store.incoming(node_id))

    def degree(self, node_id: str) -> int:
        with self._lock:
            return self._store.degree(node_id)

    def all_nodes(self) -> List[Node]:
        with self._lock:
            return self._store.all_nodes()

    def all_edges(self) -> List[Edge]:
        with self._lock:
            return self._store.all_edges()

    def node_count(self) -> int:
        with self._lock:
            return self._store.node_count()

    def edge_count(self) -> int:
        with self._lock:
            return self._store.edge_count()

    # ── index-backed queries ─────────────────────────────────

    def nodes_by_type(self, entity_type: EntityType) -> List[Node]:
        with self._lock:
            ids = self._index.nodes_by_type(entity_type)
            return [
                n for nid in ids
                if (n := self._store.get_node(nid)) is not None
            ]

    def nodes_by_name(self, prefix: str) -> List[Node]:
        with self._lock:
            ids = self._index.nodes_by_name(prefix)
            return [
                n for nid in ids
                if (n := self._store.get_node(nid)) is not None
            ]

    def edges_by_relationship(self, rel: RelationshipType) -> List[Edge]:
        with self._lock:
            pairs = self._index.edges_by_relationship(rel)
            result: List[Edge] = []
            for src, tgt in pairs:
                for edge in self._store.outgoing(src):
                    if edge.target == tgt and edge.relationship == rel:
                        result.append(edge)
            return result

    # ── serialization ────────────────────────────────────────

    def export_json(self, path: Path) -> None:
        with self._lock:
            GraphSerializer.export_graph(
                self._store.all_nodes(),
                self._store.all_edges(),
                path,
            )

    def import_json(self, path: Path) -> None:
        nodes, edges = GraphSerializer.import_graph(path)
        with self._lock:
            for node in nodes:
                self._store.add_node(node)
                self._index.index_node(node)
            for edge in edges:
                if self._store.add_edge(edge):
                    self._index.index_edge(
                        edge.source, edge.target, edge.relationship,
                    )

    # ── statistics ───────────────────────────────────────────

    def stats(self) -> GraphStats:
        with self._lock:
            nc = self._store.node_count()
            ec = self._store.edge_count()

            node_types: Dict[str, int] = {}
            for node in self._store.all_nodes():
                t = node.type.value
                node_types[t] = node_types.get(t, 0) + 1

            edge_types: Dict[str, int] = {}
            for edge in self._store.all_edges():
                r = edge.relationship.value
                edge_types[r] = edge_types.get(r, 0) + 1

            total_degree = sum(
                self._store.degree(n.id) for n in self._store.all_nodes()
            )
            avg_degree = total_degree / nc if nc else 0.0

            max_edges = nc * (nc - 1) if nc > 1 else 1
            density = ec / max_edges if max_edges else 0.0

            components = self._connected_components_count()

            return GraphStats(
                node_count=nc,
                edge_count=ec,
                node_types=node_types,
                edge_types=edge_types,
                avg_degree=round(avg_degree, 4),
                density=round(density, 6),
                connected_components=components,
            )

    def _connected_components_count(self) -> int:
        visited: Set[str] = set()
        count = 0
        for node in self._store.all_nodes():
            if node.id in visited:
                continue
            count += 1
            queue: deque[str] = deque([node.id])
            while queue:
                current = queue.popleft()
                if current in visited:
                    continue
                visited.add(current)
                for neighbor in self._store.neighbors(current):
                    if neighbor not in visited:
                        queue.append(neighbor)
        return count
