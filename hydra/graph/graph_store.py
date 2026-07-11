"""Knowledge graph storage engine with O(1) lookups."""

from __future__ import annotations

import logging
from typing import Dict, List, Optional, Set

from hydra.graph.models import Edge, Node

logger = logging.getLogger("hydra.graph.store")


class GraphStore:
    """
    In-memory graph store with fast lookups.

    Thread-safety: not thread-safe. Wrap with locks if needed.
    """

    def __init__(self) -> None:
        self._nodes: Dict[str, Node] = {}
        self._edges: Dict[tuple, Edge] = {}  # (src, tgt, rel) → Edge
        self._outgoing: Dict[str, List[Edge]] = {}  # src → edges
        self._incoming: Dict[str, List[Edge]] = {}  # tgt → edges

    def add_node(self, node: Node) -> bool:
        """Add node, merge if exists. Returns True if new."""
        if node.id in self._nodes:
            self._nodes[node.id].merge(node)
            return False
        self._nodes[node.id] = node
        self._outgoing[node.id] = []
        self._incoming[node.id] = []
        logger.debug(f"Added node: {node.id} ({node.type.value})")
        return True

    def add_edge(self, edge: Edge) -> bool:
        """Add edge, merge if exists. Returns True if new."""
        if edge.source not in self._nodes or edge.target not in self._nodes:
            logger.warning(
                f"Edge references unknown nodes: {edge.source} → {edge.target}"
            )
            return False

        key = edge.key
        if key in self._edges:
            self._edges[key].merge(edge)
            return False

        self._edges[key] = edge
        self._outgoing[edge.source].append(edge)
        self._incoming[edge.target].append(edge)
        logger.debug(f"Added edge: {edge.source} → {edge.target} ({edge.relationship.value})")
        return True

    def remove_node(self, node_id: str) -> bool:
        """Remove node and all connected edges. Returns True if existed."""
        if node_id not in self._nodes:
            return False

        # Remove all edges
        for edge in list(self._outgoing[node_id]):
            self.remove_edge(edge.source, edge.target, edge.relationship.value)
        for edge in list(self._incoming[node_id]):
            self.remove_edge(edge.source, edge.target, edge.relationship.value)

        del self._nodes[node_id]
        del self._outgoing[node_id]
        del self._incoming[node_id]
        logger.debug(f"Removed node: {node_id}")
        return True

    def remove_edge(self, source: str, target: str, relationship: str) -> bool:
        """Remove edge. Returns True if existed."""
        key = (source, target, relationship)
        if key not in self._edges:
            return False

        edge = self._edges[key]
        del self._edges[key]
        self._outgoing[source].remove(edge)
        self._incoming[target].remove(edge)
        logger.debug(f"Removed edge: {source} → {target} ({relationship})")
        return True

    def get_node(self, node_id: str) -> Optional[Node]:
        """Get node by ID. O(1)."""
        return self._nodes.get(node_id)

    def neighbors(self, node_id: str) -> List[str]:
        """Get all neighbor IDs (outgoing + incoming). O(deg(v))."""
        if node_id not in self._nodes:
            return []
        out = {e.target for e in self._outgoing[node_id]}
        inc = {e.source for e in self._incoming[node_id]}
        return list(out | inc)

    def outgoing(self, node_id: str) -> List[Edge]:
        """Get all outgoing edges. O(1)."""
        return self._outgoing.get(node_id, [])

    def incoming(self, node_id: str) -> List[Edge]:
        """Get all incoming edges. O(1)."""
        return self._incoming.get(node_id, [])

    def degree(self, node_id: str) -> int:
        """Total degree (in + out). O(1)."""
        if node_id not in self._nodes:
            return 0
        return len(self._outgoing[node_id]) + len(self._incoming[node_id])

    def all_nodes(self) -> List[Node]:
        """Get all nodes."""
        return list(self._nodes.values())

    def all_edges(self) -> List[Edge]:
        """Get all edges."""
        return list(self._edges.values())

    def clear(self) -> None:
        """Remove all nodes and edges."""
        self._nodes.clear()
        self._edges.clear()
        self._outgoing.clear()
        self._incoming.clear()
        logger.debug("Cleared graph store")

    def node_count(self) -> int:
        """Total nodes. O(1)."""
        return len(self._nodes)

    def edge_count(self) -> int:
        """Total edges. O(1)."""
        return len(self._edges)
