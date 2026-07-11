"""Relationship inference, provenance tracking, and confidence propagation."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, List, Set, Tuple

from hydra.graph.models import Edge, EntityType, RelationshipType

if TYPE_CHECKING:
    from hydra.graph.knowledge_graph import KnowledgeGraph

logger = logging.getLogger("hydra.graph.relationship_engine")

_INFERENCE_RULES: List[Tuple[EntityType, EntityType, RelationshipType]] = [
    (EntityType.DOMAIN, EntityType.IP, RelationshipType.HOSTS),
    (EntityType.HOST, EntityType.IP, RelationshipType.HOSTS),
    (EntityType.DOMAIN, EntityType.TECHNOLOGY, RelationshipType.USES),
    (EntityType.HOST, EntityType.TECHNOLOGY, RelationshipType.USES),
    (EntityType.HOST, EntityType.SERVICE, RelationshipType.RUNS),
    (EntityType.IP, EntityType.SERVICE, RelationshipType.RUNS),
    (EntityType.CVE, EntityType.PRODUCT, RelationshipType.AFFECTS),
    (EntityType.CVE, EntityType.TECHNOLOGY, RelationshipType.AFFECTS),
    (EntityType.VULNERABILITY, EntityType.URL, RelationshipType.DISCOVERED_IN),
    (EntityType.VULNERABILITY, EntityType.HOST, RelationshipType.DISCOVERED_IN),
    (EntityType.THREAT_ACTOR, EntityType.CAMPAIGN, RelationshipType.USES),
    (EntityType.CAMPAIGN, EntityType.MALWARE, RelationshipType.USES),
    (EntityType.MALWARE, EntityType.CVE, RelationshipType.EXPLOITS),
    (EntityType.ATTACK_TECHNIQUE, EntityType.ATTACK_TACTIC, RelationshipType.BELONGS_TO),
    (EntityType.DOMAIN, EntityType.ORGANIZATION, RelationshipType.BELONGS_TO),
]


class RelationshipEngine:
    """Infers, tracks, and strengthens relationships in a KnowledgeGraph."""

    def __init__(self, graph: KnowledgeGraph) -> None:
        self._graph = graph

    def infer_relationships(self, node_id: str) -> List[Edge]:
        """Infer edges from *node_id* to every other node whose type pair matches a rule."""
        node = self._graph.get_node(node_id)
        if node is None:
            return []

        inferred: List[Edge] = []
        all_nodes = self._graph.all_nodes()
        existing = self._existing_edge_keys()

        for rule_src_type, rule_tgt_type, rel in _INFERENCE_RULES:
            if node.type == rule_src_type:
                for other in all_nodes:
                    if other.id == node_id:
                        continue
                    if other.type == rule_tgt_type:
                        key = (node_id, other.id, rel.value)
                        if key not in existing:
                            edge = Edge(
                                source=node_id,
                                target=other.id,
                                relationship=rel,
                                confidence=0.5,
                                evidence=["inferred"],
                            )
                            self._graph.add_edge(edge)
                            inferred.append(edge)
                            existing.add(key)
            if node.type == rule_tgt_type:
                for other in all_nodes:
                    if other.id == node_id:
                        continue
                    if other.type == rule_src_type:
                        key = (other.id, node_id, rel.value)
                        if key not in existing:
                            edge = Edge(
                                source=other.id,
                                target=node_id,
                                relationship=rel,
                                confidence=0.5,
                                evidence=["inferred"],
                            )
                            self._graph.add_edge(edge)
                            inferred.append(edge)
                            existing.add(key)
        return inferred

    def infer_all(self) -> int:
        """Scan every node and infer missing edges. Returns count of new edges."""
        existing = self._existing_edge_keys()
        count = 0
        nodes = self._graph.all_nodes()

        for rule_src_type, rule_tgt_type, rel in _INFERENCE_RULES:
            sources = [n for n in nodes if n.type == rule_src_type]
            targets = [n for n in nodes if n.type == rule_tgt_type]
            for src in sources:
                for tgt in targets:
                    if src.id == tgt.id:
                        continue
                    key = (src.id, tgt.id, rel.value)
                    if key not in existing:
                        edge = Edge(
                            source=src.id,
                            target=tgt.id,
                            relationship=rel,
                            confidence=0.5,
                            evidence=["inferred"],
                        )
                        self._graph.add_edge(edge)
                        existing.add(key)
                        count += 1
        return count

    def propagate_confidence(self, edge: Edge) -> float:
        """Compute edge confidence from endpoint confidences and evidence count."""
        src = self._graph.get_node(edge.source)
        tgt = self._graph.get_node(edge.target)
        src_conf = src.confidence if src else 0.5
        tgt_conf = tgt.confidence if tgt else 0.5
        evidence_bonus = min(len(edge.evidence) * 0.1, 0.3)
        raw = (src_conf * 0.4 + tgt_conf * 0.4 + evidence_bonus + 0.1)
        return max(0.0, min(1.0, round(raw, 4)))

    def update_provenance(
        self, source: str, target: str, relationship: str, provenance_id: str,
    ) -> bool:
        """Append a provenance entry to an existing edge. Returns True if found."""
        for edge in self._graph.outgoing(source):
            if edge.target == target and edge.relationship.value == relationship:
                if provenance_id not in edge.provenance:
                    edge.provenance.append(provenance_id)
                return True
        return False

    def edges_by_provenance(self, provenance_id: str) -> List[Edge]:
        """Return all edges that carry a given provenance ID."""
        return [
            e for e in self._graph.all_edges()
            if provenance_id in e.provenance
        ]

    def _existing_edge_keys(self) -> Set[Tuple[str, str, str]]:
        return {e.key for e in self._graph.all_edges()}
