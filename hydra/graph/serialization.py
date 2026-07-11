"""Graph serialization and deserialization (JSON)."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List

from hydra.graph.models import Edge, EntityType, Node, RelationshipType

logger = logging.getLogger("hydra.graph.serialization")


class GraphSerializer:
    """JSON serialization for knowledge graph."""

    @staticmethod
    def node_to_dict(node: Node) -> Dict[str, Any]:
        """Serialize node to dict."""
        return {
            "id": node.id,
            "type": node.type.value,
            "name": node.name,
            "attributes": node.attributes,
            "confidence": node.confidence,
            "source": node.source,
            "timestamp": node.timestamp,
        }

    @staticmethod
    def dict_to_node(data: Dict[str, Any]) -> Node:
        """Deserialize node from dict."""
        return Node(
            id=data["id"],
            type=EntityType(data["type"]),
            name=data["name"],
            attributes=data.get("attributes", {}),
            confidence=data.get("confidence", 1.0),
            source=data.get("source", "unknown"),
            timestamp=data.get("timestamp", 0.0),
        )

    @staticmethod
    def edge_to_dict(edge: Edge) -> Dict[str, Any]:
        """Serialize edge to dict."""
        return {
            "source": edge.source,
            "target": edge.target,
            "relationship": edge.relationship.value,
            "confidence": edge.confidence,
            "evidence": edge.evidence,
            "timestamp": edge.timestamp,
        }

    @staticmethod
    def dict_to_edge(data: Dict[str, Any]) -> Edge:
        """Deserialize edge from dict."""
        return Edge(
            source=data["source"],
            target=data["target"],
            relationship=RelationshipType(data["relationship"]),
            confidence=data.get("confidence", 1.0),
            evidence=data.get("evidence", []),
            timestamp=data.get("timestamp", 0.0),
        )

    @staticmethod
    def export_graph(nodes: List[Node], edges: List[Edge], path: Path) -> None:
        """Export graph to JSON file."""
        data = {
            "nodes": [GraphSerializer.node_to_dict(n) for n in nodes],
            "edges": [GraphSerializer.edge_to_dict(e) for e in edges],
        }
        path.write_text(json.dumps(data, indent=2))
        logger.info(f"Exported graph: {len(nodes)} nodes, {len(edges)} edges → {path}")

    @staticmethod
    def import_graph(path: Path) -> tuple[List[Node], List[Edge]]:
        """Import graph from JSON file."""
        data = json.loads(path.read_text())
        nodes = [GraphSerializer.dict_to_node(n) for n in data.get("nodes", [])]
        edges = [GraphSerializer.dict_to_edge(e) for e in data.get("edges", [])]
        logger.info(f"Imported graph: {len(nodes)} nodes, {len(edges)} edges ← {path}")
        return nodes, edges
