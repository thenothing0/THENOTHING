"""Knowledge Builder Service (Phase 10.6).

Constructs and maintains the knowledge graph from all intelligence
sources. Discovers relationships, identifies gaps, and recommends
knowledge enrichment actions.
"""

import logging
import time
from typing import Any

from hydra.services.base import BaseService

logger = logging.getLogger("hydra.services.knowledge_builder")

NODE_TYPES = (
    "target", "asset", "finding", "pattern", "chain",
    "technique", "tool", "vuln_class", "technology",
)

EDGE_TYPES = (
    "has_finding", "uses_technique", "exploits_vuln",
    "targets_asset", "chains_to", "detected_by",
    "mitigated_by", "related_to",
)


class KnowledgeBuilderService(BaseService):
    """Knowledge graph construction and enrichment."""

    def __init__(self, event_bus, data_dir=None):
        super().__init__(event_bus, data_dir)
        self._nodes: dict[str, dict] = {}
        self._edges: list[dict] = []

    def add_node(self, node_id: str, node_type: str,
                 properties: dict | None = None) -> dict:
        """Add a node to the knowledge graph."""
        if node_type not in NODE_TYPES:
            return {"status": "error", "error": f"Unknown node type: {node_type}"}

        node = {
            "id": node_id,
            "type": node_type,
            "properties": properties or {},
            "created_at": time.time(),
            "updated_at": time.time(),
        }
        self._nodes[node_id] = node

        self._emit("knowledge_builder.node_added", {
            "node_id": node_id, "node_type": node_type,
        })
        return {"status": "added", **node}

    def add_edge(self, source: str, target: str,
                 edge_type: str, weight: float = 1.0) -> dict:
        """Add an edge between two nodes."""
        if edge_type not in EDGE_TYPES:
            return {"status": "error", "error": f"Unknown edge type: {edge_type}"}
        if source not in self._nodes:
            return {"status": "error", "error": f"Source node not found: {source}"}
        if target not in self._nodes:
            return {"status": "error", "error": f"Target node not found: {target}"}

        edge = {
            "source": source,
            "target": target,
            "type": edge_type,
            "weight": weight,
            "created_at": time.time(),
        }
        self._edges.append(edge)

        self._emit("knowledge_builder.edge_added", {
            "source": source, "target": target, "edge_type": edge_type,
        })
        return {"status": "added", **edge}

    def find_gaps(self) -> dict:
        """Identify knowledge gaps — nodes with few connections."""
        connected: dict[str, int] = {}
        for n in self._nodes:
            connected[n] = 0
        for e in self._edges:
            connected[e["source"]] = connected.get(e["source"], 0) + 1
            connected[e["target"]] = connected.get(e["target"], 0) + 1

        orphans = [nid for nid, count in connected.items() if count == 0]
        weak = [nid for nid, count in connected.items() if 0 < count <= 1]

        recommendations = []
        for oid in orphans[:5]:
            node = self._nodes[oid]
            recommendations.append({
                "action": "enrich",
                "node_id": oid,
                "node_type": node["type"],
                "reason": "Orphan node with no connections",
            })

        return {
            "total_nodes": len(self._nodes),
            "total_edges": len(self._edges),
            "orphan_count": len(orphans),
            "weak_count": len(weak),
            "orphans": orphans[:10],
            "weak_nodes": weak[:10],
            "recommendations": recommendations,
        }

    def get_subgraph(self, node_id: str, depth: int = 1) -> dict:
        """Get a subgraph centered on a node."""
        if node_id not in self._nodes:
            return {"status": "error", "error": "Node not found"}

        visited = {node_id}
        frontier = {node_id}
        collected_edges = []

        for _ in range(depth):
            next_frontier = set()
            for e in self._edges:
                if e["source"] in frontier:
                    next_frontier.add(e["target"])
                    collected_edges.append(e)
                if e["target"] in frontier:
                    next_frontier.add(e["source"])
                    collected_edges.append(e)
            frontier = next_frontier - visited
            visited |= frontier

        nodes = [self._nodes[nid] for nid in visited if nid in self._nodes]
        return {
            "center": node_id,
            "depth": depth,
            "nodes": nodes,
            "edges": collected_edges,
            "node_count": len(nodes),
            "edge_count": len(collected_edges),
        }

    def build_from_findings(self, findings: list[dict]) -> dict:
        """Auto-build graph nodes and edges from findings."""
        nodes_added = 0
        edges_added = 0

        for f in findings:
            fid = f.get("id", f"f-{int(time.time()*1000)}")
            target = f.get("target", "")
            vuln_class = f.get("vuln_class", "")

            self.add_node(fid, "finding", f)
            nodes_added += 1

            if target:
                if target not in self._nodes:
                    self.add_node(target, "target", {"name": target})
                    nodes_added += 1
                self.add_edge(target, fid, "has_finding")
                edges_added += 1

            if vuln_class:
                if vuln_class not in self._nodes:
                    self.add_node(vuln_class, "vuln_class", {"name": vuln_class})
                    nodes_added += 1
                self.add_edge(fid, vuln_class, "exploits_vuln")
                edges_added += 1

        self._emit("knowledge_builder.built_from_findings", {
            "findings": len(findings),
            "nodes_added": nodes_added,
            "edges_added": edges_added,
        })

        return {
            "status": "built",
            "findings_processed": len(findings),
            "nodes_added": nodes_added,
            "edges_added": edges_added,
            "total_nodes": len(self._nodes),
            "total_edges": len(self._edges),
        }

    def get_stats(self) -> dict[str, Any]:
        by_type: dict[str, int] = {}
        for n in self._nodes.values():
            t = n.get("type", "unknown")
            by_type[t] = by_type.get(t, 0) + 1
        edge_types: dict[str, int] = {}
        for e in self._edges:
            et = e.get("type", "unknown")
            edge_types[et] = edge_types.get(et, 0) + 1
        return {
            "total_nodes": len(self._nodes),
            "total_edges": len(self._edges),
            "nodes_by_type": by_type,
            "edges_by_type": edge_types,
            "node_types": list(NODE_TYPES),
            "edge_types": list(EDGE_TYPES),
        }
