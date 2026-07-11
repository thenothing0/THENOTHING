"""KnowledgeGraphEngineService — unified service wrapping the graph intelligence stack."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict

from hydra.graph.intelligence import GraphIntelligence
from hydra.graph.knowledge_graph import KnowledgeGraph
from hydra.graph.models import Edge, GraphStats, Node
from hydra.graph.query import GraphQueryEngine
from hydra.graph.relationship_engine import RelationshipEngine
from hydra.services.base import BaseService
from hydra.services.event_bus import EventBus

logger = logging.getLogger("hydra.services.knowledge_graph_engine")


class KnowledgeGraphEngineService(BaseService):
    """Facade service exposing KnowledgeGraph + query + relationships + intelligence."""

    def __init__(self, event_bus: EventBus, data_dir: Path | None = None) -> None:
        super().__init__(event_bus, data_dir)
        self._graph = KnowledgeGraph(normalize=True)
        self._query = GraphQueryEngine(self._graph)
        self._relationships = RelationshipEngine(self._graph)
        self._intelligence = GraphIntelligence(self._graph)

    # ── graph access ────────────────────────────────────────────

    @property
    def graph(self) -> KnowledgeGraph:
        return self._graph

    @property
    def query(self) -> GraphQueryEngine:
        return self._query

    @property
    def relationships(self) -> RelationshipEngine:
        return self._relationships

    @property
    def intelligence(self) -> GraphIntelligence:
        return self._intelligence

    # ── delegated mutations with events ─────────────────────────

    def add_node(self, node: Node) -> bool:
        is_new = self._graph.add_node(node)
        if is_new:
            self._emit("knowledge_graph.node_added", {
                "node_id": node.id, "type": node.type.value,
            })
        return is_new

    def add_edge(self, edge: Edge) -> bool:
        is_new = self._graph.add_edge(edge)
        if is_new:
            self._emit("knowledge_graph.edge_added", {
                "source": edge.source, "target": edge.target,
                "relationship": edge.relationship.value,
            })
        return is_new

    def infer_all(self) -> int:
        count = self._relationships.infer_all()
        if count > 0:
            self._emit("knowledge_graph.links_inferred", {"count": count})
        return count

    # ── stats / health ──────────────────────────────────────────

    def stats(self) -> GraphStats:
        return self._graph.stats()

    def get_health(self) -> Dict[str, Any]:
        s = self._graph.stats()
        return {
            "status": "healthy" if s.node_count > 0 else "empty",
            "node_count": s.node_count,
            "edge_count": s.edge_count,
            "components": s.connected_components,
        }
