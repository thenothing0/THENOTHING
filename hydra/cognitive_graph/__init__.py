"""
╔══════════════════════════════════════════════════════════════╗
║  Target Cognitive Graph — Dynamic Attack Surface Memory      ║
║  Temporal graphing, relational intelligence, infrastructure  ║
║  evolution tracking, cross-target correlation                ║
╚══════════════════════════════════════════════════════════════╝
"""

import json
import logging
import time
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger("hydra.cognitive_graph")


class NodeType(str, Enum):
    ASSET = "asset"
    API = "api"
    IDENTITY = "identity"
    SESSION = "session"
    INFRASTRUCTURE = "infrastructure"
    TRUST_RELATIONSHIP = "trust_relationship"
    CLOUD_RESOURCE = "cloud_resource"
    K8S_OBJECT = "k8s_object"
    TECHNOLOGY = "technology"
    WORKFLOW_STATE = "workflow_state"
    EXPLOIT_PATH = "exploit_path"
    HISTORICAL_EXPOSURE = "historical_exposure"
    OWNERSHIP = "ownership"


class EdgeRelation(str, Enum):
    HOSTS = "hosts"
    AUTHENTICATES = "authenticates"
    TRUSTS = "trusts"
    EXPOSES = "exposes"
    CONNECTS_TO = "connects_to"
    DEPENDS_ON = "depends_on"
    ESCALATES_TO = "escalates_to"
    CONTAINS = "contains"
    CORRELATES = "correlates"
    EVOLVED_FROM = "evolved_from"
    REPLACED_BY = "replaced_by"
    DISCOVERED_VIA = "discovered_via"


@dataclass
class GraphNode:
    """A node in the cognitive attack-surface graph."""
    id: str
    name: str
    node_type: NodeType
    properties: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    confidence: float = 0.5
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    source: str = ""              # recon, osint, crawl, inference, temporal
    history: List[Dict[str, Any]] = field(default_factory=list)
    risk_score: float = 0.0


@dataclass
class GraphEdge:
    """A directed edge in the cognitive graph."""
    source_id: str
    target_id: str
    relation: EdgeRelation
    confidence: float = 0.5
    properties: Dict[str, Any] = field(default_factory=dict)
    first_seen: float = field(default_factory=time.time)
    bidirectional: bool = False


@dataclass
class ExposureTimeline:
    """Timeline of exposure for an asset."""
    asset_id: str
    events: List[Dict[str, Any]] = field(default_factory=list)


class CognitiveGraph:
    """
    Dynamic Attack Surface Memory Graph.

    Stores and reasons about:
      - Assets, APIs, identities, sessions, infrastructure
      - Trust relationships, historical exposures
      - Cloud resources, Kubernetes objects, technologies
      - Workflow states, exploit paths, ownership relationships
      - Exposure timelines

    Capabilities:
      - Attack-surface comprehension
      - Blast-radius estimation
      - Lateral movement reasoning
      - Exploit-chain prediction
      - Privilege graph analysis
      - Trust-boundary inference
      - Hidden asset prediction
      - Temporal graphing
      - Infrastructure evolution tracking
      - Cross-target correlation
    """

    def __init__(self):
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: List[GraphEdge] = []
        self._adjacency: Dict[str, List[Tuple[str, EdgeRelation]]] = {}
        self._reverse_adj: Dict[str, List[Tuple[str, EdgeRelation]]] = {}
        self._timelines: Dict[str, ExposureTimeline] = {}
        self._by_type: Dict[str, List[str]] = {}

    # ── Node Operations ───────────────────────

    def add_node(self, node: GraphNode) -> str:
        existing = self._nodes.get(node.id)
        if existing:
            existing.last_seen = time.time()
            existing.confidence = max(existing.confidence, node.confidence)
            existing.properties.update(node.properties)
            existing.history.append({"updated": time.time(), "source": node.source})
            return node.id

        self._nodes[node.id] = node
        self._adjacency.setdefault(node.id, [])
        self._reverse_adj.setdefault(node.id, [])
        self._by_type.setdefault(node.node_type.value, []).append(node.id)
        return node.id

    def add_edge(self, edge: GraphEdge):
        self._edges.append(edge)
        self._adjacency.setdefault(edge.source_id, []).append(
            (edge.target_id, edge.relation))
        self._reverse_adj.setdefault(edge.target_id, []).append(
            (edge.source_id, edge.relation))
        if edge.bidirectional:
            self._adjacency.setdefault(edge.target_id, []).append(
                (edge.source_id, edge.relation))
            self._reverse_adj.setdefault(edge.source_id, []).append(
                (edge.target_id, edge.relation))

    def node(self, id: str, name: str, ntype: NodeType, **props) -> GraphNode:
        n = GraphNode(id=id, name=name, node_type=ntype, properties=props)
        self.add_node(n)
        return n

    def relate(self, src: str, tgt: str, rel: EdgeRelation,
               confidence: float = 0.5, **props):
        e = GraphEdge(source_id=src, target_id=tgt, relation=rel,
                      confidence=confidence, properties=props)
        self.add_edge(e)

    # ── Query Operations ──────────────────────

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        return self._nodes.get(node_id)

    def get_by_type(self, ntype: NodeType) -> List[GraphNode]:
        ids = self._by_type.get(ntype.value, [])
        return [self._nodes[i] for i in ids if i in self._nodes]

    def get_neighbors(self, node_id: str,
                      relation: Optional[EdgeRelation] = None) -> List[GraphNode]:
        neighbors = []
        for tgt_id, rel in self._adjacency.get(node_id, []):
            if relation and rel != relation:
                continue
            n = self._nodes.get(tgt_id)
            if n:
                neighbors.append(n)
        return neighbors

    def find_path(self, from_id: str, to_id: str,
                  max_depth: int = 10) -> Optional[List[str]]:
        if from_id not in self._nodes or to_id not in self._nodes:
            return None
        visited: Set[str] = set()
        queue = [(from_id, [from_id])]
        while queue:
            current, path = queue.pop(0)
            if current == to_id:
                return path
            if current in visited or len(path) > max_depth:
                continue
            visited.add(current)
            for nxt, _ in self._adjacency.get(current, []):
                if nxt not in visited:
                    queue.append((nxt, path + [nxt]))
        return None

    # ── Attack Surface Intelligence ───────────

    def estimate_blast_radius(self, compromised_node_id: str,
                              max_depth: int = 5) -> Dict[str, Any]:
        """Estimate blast radius from a compromised node."""
        affected: Set[str] = set()
        queue = [(compromised_node_id, 0)]
        visited: Set[str] = set()

        while queue:
            current, depth = queue.pop(0)
            if depth > max_depth or current in visited:
                continue
            visited.add(current)
            affected.add(current)

            for tgt_id, rel in self._adjacency.get(current, []):
                if rel in (EdgeRelation.TRUSTS, EdgeRelation.CONNECTS_TO,
                           EdgeRelation.ESCALATES_TO, EdgeRelation.CONTAINS):
                    queue.append((tgt_id, depth + 1))

        affected_nodes = [self._nodes[nid] for nid in affected if nid in self._nodes]
        by_type = {}
        for n in affected_nodes:
            by_type[n.node_type.value] = by_type.get(n.node_type.value, 0) + 1

        return {
            "compromised": compromised_node_id,
            "affected_count": len(affected),
            "affected_by_type": by_type,
            "max_depth_reached": max_depth,
            "critical_assets": [n.name for n in affected_nodes
                                if n.risk_score > 0.7],
        }

    def find_lateral_movement_paths(self, from_id: str) -> List[List[str]]:
        """Find all lateral movement paths from a node."""
        paths = []
        lateral_rels = {EdgeRelation.TRUSTS, EdgeRelation.CONNECTS_TO,
                        EdgeRelation.ESCALATES_TO}

        def walk(current: str, path: List[str], visited: Set[str]):
            for tgt_id, rel in self._adjacency.get(current, []):
                if tgt_id in visited or rel not in lateral_rels:
                    continue
                new_path = path + [tgt_id]
                paths.append(new_path)
                if len(new_path) < 8:
                    walk(tgt_id, new_path, visited | {tgt_id})

        walk(from_id, [from_id], {from_id})
        return paths

    def predict_exploit_chains(self) -> List[Dict[str, Any]]:
        """Predict possible exploit chains from the graph."""
        chains = []
        exploit_nodes = self.get_by_type(NodeType.EXPLOIT_PATH)
        for ep in exploit_nodes:
            targets = self.get_neighbors(ep.id, EdgeRelation.ESCALATES_TO)
            for target in targets:
                chains.append({
                    "entry": ep.name,
                    "target": target.name,
                    "confidence": min(ep.confidence, target.confidence),
                    "risk": max(ep.risk_score, target.risk_score),
                })
        chains.sort(key=lambda c: c["confidence"], reverse=True)
        return chains

    def infer_hidden_assets(self) -> List[Dict[str, Any]]:
        """Infer hidden assets from naming patterns and relationships."""
        predictions = []
        assets = self.get_by_type(NodeType.ASSET)

        # Naming pattern inference
        names = [a.name for a in assets]
        for name in names:
            if "api" in name.lower():
                predictions.append({
                    "predicted": name.replace("api", "admin-api"),
                    "reason": "API naming pattern suggests admin API",
                    "confidence": 0.3,
                })
            if "prod" in name.lower():
                predictions.append({
                    "predicted": name.replace("prod", "staging"),
                    "reason": "Production asset suggests staging equivalent",
                    "confidence": 0.4,
                })
            if "-v2" in name.lower():
                predictions.append({
                    "predicted": name.replace("-v2", "-v1"),
                    "reason": "Versioned API suggests legacy version",
                    "confidence": 0.5,
                })

        return predictions

    # ── Temporal Intelligence ─────────────────

    def record_timeline_event(self, asset_id: str, event: Dict[str, Any]):
        """Record a temporal event for an asset."""
        if asset_id not in self._timelines:
            self._timelines[asset_id] = ExposureTimeline(asset_id=asset_id)
        event["timestamp"] = event.get("timestamp", time.time())
        self._timelines[asset_id].events.append(event)

    def get_timeline(self, asset_id: str) -> Optional[ExposureTimeline]:
        return self._timelines.get(asset_id)

    def get_infrastructure_changes(self, since: float = 0) -> List[Dict[str, Any]]:
        """Get infrastructure changes since a timestamp."""
        changes = []
        for node in self._nodes.values():
            for h in node.history:
                if h.get("updated", 0) > since:
                    changes.append({
                        "node": node.name,
                        "type": node.node_type.value,
                        "change_time": h["updated"],
                        "source": h.get("source", ""),
                    })
        changes.sort(key=lambda c: c["change_time"], reverse=True)
        return changes

    # ── Persistence ───────────────────────────

    def export_json(self, path: str):
        """Export graph to JSON."""
        data = {
            "nodes": {nid: {
                "id": n.id, "name": n.name, "type": n.node_type.value,
                "confidence": n.confidence, "risk": n.risk_score,
                "first_seen": n.first_seen, "last_seen": n.last_seen,
                "properties": n.properties, "tags": n.tags,
            } for nid, n in self._nodes.items()},
            "edges": [{
                "source": e.source_id, "target": e.target_id,
                "relation": e.relation.value, "confidence": e.confidence,
            } for e in self._edges],
            "metadata": {"exported_at": time.time(), "node_count": len(self._nodes),
                          "edge_count": len(self._edges)},
        }
        Path(path).write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")

    # ── Summary ───────────────────────────────

    def get_summary(self) -> Dict[str, Any]:
        by_type = {}
        for n in self._nodes.values():
            by_type[n.node_type.value] = by_type.get(n.node_type.value, 0) + 1
        return {
            "nodes": len(self._nodes),
            "edges": len(self._edges),
            "by_type": by_type,
            "timelines": len(self._timelines),
            "high_risk_nodes": len([n for n in self._nodes.values() if n.risk_score > 0.7]),
        }
