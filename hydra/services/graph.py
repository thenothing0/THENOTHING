"""Knowledge Graph Service — typed entity-relationship graph queries.

Wraps KnowledgeGraphIndex and WikiStore to provide structured graph
operations: typed relationships, subgraph extraction, entity resolution,
and attack path discovery. All queries are read-only over the canonical wiki.
"""

import logging
from typing import Any

from hydra.services.base import BaseService

logger = logging.getLogger("hydra.services.graph")

RELATIONSHIP_TYPES = (
    "references", "exploits", "mitigates", "chains_to",
    "escalates_to", "requires", "enhances", "contradicts",
    "confirms", "related_to",
)


class GraphService(BaseService):
    """Typed knowledge graph queries over the wiki."""

    def _index(self):
        from hydra.knowledge.graph_index import KnowledgeGraphIndex
        return KnowledgeGraphIndex()

    def _store(self):
        from hydra.knowledge.wiki_store import WikiStore
        return WikiStore()

    def neighbors(self, slug: str, *, direction: str = "both",
                  node_type: str = "") -> list[dict]:
        """Get neighbors of a node with optional type filter."""
        try:
            idx = self._index()
            raw = idx.neighbors(slug)
            results = []
            store = self._store()
            for neighbor_slug in raw:
                page = store.read(neighbor_slug)
                if page is None:
                    results.append({
                        "slug": neighbor_slug, "type": "unknown",
                        "title": neighbor_slug, "direction": "outbound",
                    })
                    continue
                ntype = page.meta.get("type", "unknown")
                if node_type and ntype != node_type:
                    continue
                results.append({
                    "slug": neighbor_slug,
                    "type": ntype,
                    "title": page.meta.get("title", neighbor_slug),
                    "direction": "linked",
                })
            return results
        except Exception as e:
            logger.error("neighbors(%s) failed: %s", slug, e)
            return []

    def shortest_path(self, source: str, target: str) -> list[str]:
        """Find shortest path between two nodes."""
        try:
            idx = self._index()
            return idx.shortest_path(source, target)
        except Exception as e:
            logger.error("shortest_path failed: %s", e)
            return []

    def subgraph(self, center: str, *, depth: int = 2) -> dict:
        """Extract a subgraph around a center node."""
        try:
            idx = self._index()
            store = self._store()
            visited: set[str] = set()
            edges: list[dict] = []
            nodes: list[dict] = []
            frontier = {center}

            for _ in range(depth):
                next_frontier: set[str] = set()
                for slug in frontier:
                    if slug in visited:
                        continue
                    visited.add(slug)
                    page = store.read(slug)
                    ntype = page.meta.get("type", "unknown") if page else "unknown"
                    title = page.meta.get("title", slug) if page else slug
                    nodes.append({"slug": slug, "type": ntype, "title": title})
                    for neighbor in idx.neighbors(slug):
                        edges.append({"source": slug, "target": neighbor})
                        if neighbor not in visited:
                            next_frontier.add(neighbor)
                frontier = next_frontier

            return {
                "center": center,
                "depth": depth,
                "nodes": nodes,
                "edges": edges,
                "node_count": len(nodes),
                "edge_count": len(edges),
            }
        except Exception as e:
            logger.error("subgraph failed: %s", e)
            return {"center": center, "nodes": [], "edges": [],
                    "node_count": 0, "edge_count": 0}

    def attack_paths(self, start_type: str = "asset",
                     end_type: str = "finding",
                     max_depth: int = 5) -> list[list[str]]:
        """Find attack paths between node types."""
        try:
            idx = self._index()
            return idx.attack_paths(start_type, end_type, max_depth)
        except Exception as e:
            logger.error("attack_paths failed: %s", e)
            return []

    def entities_by_type(self, node_type: str, limit: int = 50) -> list[dict]:
        """List all entities of a given type."""
        try:
            from hydra.knowledge.schema import NodeType
            store = self._store()
            ntype = NodeType(node_type)
            pages = list(store.iter_pages(ntype))
            results = []
            for p in pages[:limit]:
                results.append({
                    "slug": p.slug,
                    "type": node_type,
                    "title": p.meta.get("title", p.slug),
                    "link_count": len(p.links) if hasattr(p, "links") else 0,
                })
            return results
        except Exception as e:
            logger.error("entities_by_type(%s) failed: %s", node_type, e)
            return []

    def get_stats(self) -> dict[str, Any]:
        """Graph statistics."""
        try:
            idx = self._index()
            store = self._store()
            from hydra.knowledge.schema import NodeType
            type_counts = {}
            total = 0
            for ntype in NodeType:
                count = len(list(store.iter_pages(ntype)))
                if count > 0:
                    type_counts[ntype.value] = count
                    total += count
            return {
                "total_nodes": total,
                "total_edges": sum(len(v) for v in idx._adj.values()) if hasattr(idx, "_adj") else 0,
                "types": type_counts,
                "relationship_types": list(RELATIONSHIP_TYPES),
            }
        except Exception as e:
            logger.error("get_stats failed: %s", e)
            return {"total_nodes": 0, "total_edges": 0, "types": {}}

    def find_related(self, slug: str, *, limit: int = 10) -> list[dict]:
        """Find related entities through transitive links."""
        try:
            neighbors = self.neighbors(slug)
            related: list[dict] = []
            seen = {slug}
            for n in neighbors:
                if n["slug"] not in seen:
                    seen.add(n["slug"])
                    related.append(n)
            for n in neighbors[:5]:
                for n2 in self.neighbors(n["slug"]):
                    if n2["slug"] not in seen and len(related) < limit:
                        seen.add(n2["slug"])
                        n2["via"] = n["slug"]
                        related.append(n2)
            return related[:limit]
        except Exception:
            return []
