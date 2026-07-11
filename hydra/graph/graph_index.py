"""Knowledge graph index for fast lookups by type, attribute, and name."""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Dict, List, Set

from hydra.graph.models import EntityType, Node, RelationshipType

logger = logging.getLogger("hydra.graph.index")


class GraphIndex:
    """
    Multi-attribute index for nodes and edges.

    Maintains:
    - Nodes by type
    - Nodes by name prefix (for search)
    - Edges by relationship type
    """

    def __init__(self) -> None:
        self._nodes_by_type: Dict[EntityType, Set[str]] = defaultdict(set)
        self._nodes_by_name_prefix: Dict[str, Set[str]] = defaultdict(set)
        self._edges_by_rel: Dict[RelationshipType, List[tuple]] = defaultdict(list)

    def index_node(self, node: Node) -> None:
        """Add node to index."""
        self._nodes_by_type[node.type].add(node.id)
        # Index by name prefixes for substring search
        for i in range(1, min(len(node.name) + 1, 20)):
            prefix = node.name[:i].lower()
            self._nodes_by_name_prefix[prefix].add(node.id)

    def index_edge(self, source: str, target: str, rel: RelationshipType) -> None:
        """Add edge to index."""
        self._edges_by_rel[rel].append((source, target))

    def remove_node(self, node: Node) -> None:
        """Remove node from index."""
        self._nodes_by_type[node.type].discard(node.id)
        for i in range(1, min(len(node.name) + 1, 20)):
            prefix = node.name[:i].lower()
            self._nodes_by_name_prefix[prefix].discard(node.id)

    def remove_edge(self, source: str, target: str, rel: RelationshipType) -> None:
        """Remove edge from index."""
        try:
            self._edges_by_rel[rel].remove((source, target))
        except ValueError:
            pass

    def nodes_by_type(self, entity_type: EntityType) -> List[str]:
        """Get all node IDs of a given type. O(1) lookup."""
        return list(self._nodes_by_type[entity_type])

    def nodes_by_name(self, prefix: str) -> List[str]:
        """Get node IDs matching name prefix. Case-insensitive."""
        return list(self._nodes_by_name_prefix[prefix.lower()])

    def edges_by_relationship(self, rel: RelationshipType) -> List[tuple]:
        """Get all (source, target) pairs for a relationship type."""
        return self._edges_by_rel[rel].copy()

    def clear(self) -> None:
        """Clear all indexes."""
        self._nodes_by_type.clear()
        self._nodes_by_name_prefix.clear()
        self._edges_by_rel.clear()
