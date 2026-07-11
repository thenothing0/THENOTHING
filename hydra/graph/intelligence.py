"""Graph intelligence — link prediction, confidence propagation, contradiction detection, IOC pivoting."""

from __future__ import annotations

import logging
from collections import deque
from typing import TYPE_CHECKING, Dict, List, Set, Tuple

from hydra.graph.models import Edge, EntityType, RelationshipType

if TYPE_CHECKING:
    from hydra.graph.knowledge_graph import KnowledgeGraph

logger = logging.getLogger("hydra.graph.intelligence")


class GraphIntelligence:
    """Reasoning helpers layered on top of a KnowledgeGraph."""

    def __init__(self, graph: KnowledgeGraph) -> None:
        self._graph = graph

    # ── link prediction ─────────────────────────────────────────

    def infer_missing_links(
        self, *, min_common_neighbors: int = 2,
    ) -> List[Edge]:
        """Predict missing edges via Jaccard common-neighbor heuristic."""
        nodes = self._graph.all_nodes()
        existing_keys: Set[Tuple[str, str]] = set()
        for e in self._graph.all_edges():
            existing_keys.add((e.source, e.target))
            existing_keys.add((e.target, e.source))

        neighbor_map: Dict[str, Set[str]] = {}
        for n in nodes:
            neighbor_map[n.id] = set(self._graph.neighbors(n.id))

        predicted: List[Edge] = []
        seen: Set[Tuple[str, str]] = set()
        for i, a in enumerate(nodes):
            for b in nodes[i + 1:]:
                if (a.id, b.id) in existing_keys:
                    continue
                common = neighbor_map.get(a.id, set()) & neighbor_map.get(b.id, set())
                if len(common) >= min_common_neighbors:
                    pair = (min(a.id, b.id), max(a.id, b.id))
                    if pair in seen:
                        continue
                    seen.add(pair)
                    union = neighbor_map.get(a.id, set()) | neighbor_map.get(b.id, set())
                    jaccard = len(common) / len(union) if union else 0.0
                    predicted.append(Edge(
                        source=a.id,
                        target=b.id,
                        relationship=RelationshipType.RELATED_TO,
                        confidence=round(min(jaccard, 1.0), 4),
                        evidence=[f"common_neighbors:{len(common)}"],
                    ))
        predicted.sort(key=lambda e: e.confidence, reverse=True)
        return predicted

    # ── confidence propagation ──────────────────────────────────

    def propagate_confidence(
        self, *, iterations: int = 3, decay: float = 0.7,
    ) -> Dict[str, float]:
        """Iterative neighbor-based confidence propagation."""
        nodes = self._graph.all_nodes()
        scores: Dict[str, float] = {n.id: n.confidence for n in nodes}
        for _ in range(iterations):
            new_scores: Dict[str, float] = {}
            for n in nodes:
                neighbors = self._graph.neighbors(n.id)
                if not neighbors:
                    new_scores[n.id] = scores[n.id]
                    continue
                neighbor_avg = sum(scores.get(nb, 0.0) for nb in neighbors) / len(neighbors)
                new_scores[n.id] = max(0.0, min(1.0,
                    round(scores[n.id] * (1 - decay) + neighbor_avg * decay, 6)))
            scores = new_scores
        return scores

    # ── evidence aggregation ────────────────────────────────────

    def aggregate_evidence(self, node_id: str) -> Dict:
        """Collect all evidence from inbound edges to a node."""
        incoming = self._graph.incoming(node_id)
        all_evidence: List[str] = []
        all_provenance: List[str] = []
        sources: List[str] = []
        for edge in incoming:
            all_evidence.extend(edge.evidence)
            all_provenance.extend(edge.provenance)
            sources.append(edge.source)
        return {
            "node_id": node_id,
            "evidence": list(dict.fromkeys(all_evidence)),
            "provenance": list(dict.fromkeys(all_provenance)),
            "sources": list(dict.fromkeys(sources)),
            "edge_count": len(incoming),
        }

    # ── duplicate detection ─────────────────────────────────────

    def detect_duplicates(
        self, *, threshold: float = 0.8,
    ) -> List[Tuple[str, str, float]]:
        """Find nodes with similar names via Jaccard token similarity."""
        nodes = self._graph.all_nodes()
        token_cache: Dict[str, Set[str]] = {}
        for n in nodes:
            token_cache[n.id] = set(
                f"{n.name} {n.id} {' '.join(str(v) for v in n.attributes.values())}".lower().split()
            )

        duplicates: List[Tuple[str, str, float]] = []
        for i, a in enumerate(nodes):
            for b in nodes[i + 1:]:
                if a.type != b.type:
                    continue
                ta, tb = token_cache[a.id], token_cache[b.id]
                if not ta or not tb:
                    continue
                jaccard = len(ta & tb) / len(ta | tb)
                if jaccard >= threshold:
                    duplicates.append((a.id, b.id, round(jaccard, 4)))
        duplicates.sort(key=lambda x: x[2], reverse=True)
        return duplicates

    # ── contradiction detection ─────────────────────────────────

    def detect_contradictions(self) -> List[Dict]:
        """Find conflicting edge types between the same node pair."""
        edge_map: Dict[Tuple[str, str], List[Edge]] = {}
        for e in self._graph.all_edges():
            key = (e.source, e.target)
            edge_map.setdefault(key, []).append(e)

        _CONFLICTS = {
            (RelationshipType.HOSTS, RelationshipType.TARGETS),
            (RelationshipType.TARGETS, RelationshipType.HOSTS),
            (RelationshipType.MITIGATED_BY, RelationshipType.EXPLOITS),
            (RelationshipType.EXPLOITS, RelationshipType.MITIGATED_BY),
        }

        contradictions: List[Dict] = []
        for (src, tgt), edges in edge_map.items():
            if len(edges) < 2:
                continue
            rels = {e.relationship for e in edges}
            for r1 in rels:
                for r2 in rels:
                    if (r1, r2) in _CONFLICTS:
                        contradictions.append({
                            "source": src,
                            "target": tgt,
                            "relationships": [r1.value, r2.value],
                            "edges": edges,
                        })
        return contradictions

    # ── attack chain reconstruction ─────────────────────────────

    def reconstruct_attack_chains(
        self,
        entry_type: EntityType,
        target_type: EntityType,
        *,
        max_depth: int = 6,
    ) -> List[List[str]]:
        """Type-constrained DFS chains from entry_type nodes to target_type nodes."""
        entries = [n for n in self._graph.all_nodes() if n.type == entry_type]
        targets = {n.id for n in self._graph.all_nodes() if n.type == target_type}
        chains: List[List[str]] = []

        for entry in entries:
            self._dfs_chain(entry.id, targets, [entry.id], set(), max_depth, chains)
        return chains

    def _dfs_chain(
        self,
        current: str,
        targets: Set[str],
        path: List[str],
        visited: Set[str],
        max_depth: int,
        results: List[List[str]],
    ) -> None:
        if len(path) > max_depth:
            return
        if current in targets and len(path) > 1:
            results.append(list(path))
            return
        visited.add(current)
        for edge in self._graph.outgoing(current):
            if edge.target not in visited:
                self._dfs_chain(
                    edge.target, targets, path + [edge.target],
                    visited, max_depth, results,
                )
        visited.discard(current)

    # ── IOC pivoting ────────────────────────────────────────────

    def ioc_pivot(self, ioc_id: str, *, max_depth: int = 3) -> Dict:
        """Multi-hop pivot from an IOC to related entities."""
        node = self._graph.get_node(ioc_id)
        if node is None:
            return {"ioc_id": ioc_id, "found": False, "related": {}}

        related: Dict[str, List[str]] = {}
        visited: Set[str] = {ioc_id}
        queue: deque[Tuple[str, int]] = deque([(ioc_id, 0)])

        while queue:
            current, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for nb in self._graph.neighbors(current):
                if nb in visited:
                    continue
                visited.add(nb)
                nb_node = self._graph.get_node(nb)
                if nb_node:
                    t = nb_node.type.value
                    related.setdefault(t, []).append(nb)
                queue.append((nb, depth + 1))

        return {"ioc_id": ioc_id, "found": True, "related": related}

    # ── risk summary ────────────────────────────────────────────

    def risk_summary(self) -> Dict:
        """Aggregate risk metrics from the graph."""
        nodes = self._graph.all_nodes()
        vulns = [n for n in nodes if n.type in (EntityType.VULNERABILITY, EntityType.CVE)]
        high_conf = [n for n in vulns if n.confidence >= 0.8]
        return {
            "total_nodes": len(nodes),
            "total_edges": self._graph.edge_count(),
            "vulnerability_count": len(vulns),
            "high_confidence_vulns": len(high_conf),
            "avg_confidence": round(
                sum(n.confidence for n in nodes) / len(nodes), 4
            ) if nodes else 0.0,
        }
