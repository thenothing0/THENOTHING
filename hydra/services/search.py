"""Search Service — hybrid keyword + semantic + graph search.

Combines three search strategies into a unified ranked result set:
1. Keyword — token overlap via WikiStore.search()
2. Graph — topology-aware via KnowledgeGraphIndex neighbors/paths
3. Semantic — (future) embedding-based similarity

Results are fused with reciprocal rank fusion (RRF).
"""

import logging
from typing import Any

from hydra.services.base import BaseService

logger = logging.getLogger("hydra.services.search")

SEARCH_MODES = ("keyword", "graph", "hybrid", "semantic")
ENTITY_TYPES = ("report", "intel", "finding", "pattern", "chain", "technique", "asset")


class SearchResult:
    __slots__ = ("slug", "title", "score", "source", "snippet", "node_type", "metadata")

    def __init__(self, slug: str, title: str = "", score: float = 0.0,
                 source: str = "keyword", snippet: str = "",
                 node_type: str = "", metadata: dict | None = None):
        self.slug = slug
        self.title = title or slug
        self.score = score
        self.source = source
        self.snippet = snippet
        self.node_type = node_type
        self.metadata = metadata or {}

    def to_dict(self) -> dict:
        return {
            "slug": self.slug,
            "title": self.title,
            "score": round(self.score, 4),
            "source": self.source,
            "snippet": self.snippet,
            "node_type": self.node_type,
            "metadata": self.metadata,
        }


class SearchService(BaseService):
    """Hybrid search across the knowledge base."""

    def search(self, query: str, mode: str = "hybrid",
               node_type: str = "", limit: int = 20,
               target: str = "") -> list[dict]:
        """Search with the specified mode and return fused results."""
        if mode not in SEARCH_MODES:
            mode = "hybrid"

        results: list[SearchResult] = []

        if mode in ("keyword", "hybrid"):
            results.extend(self._keyword_search(query, node_type, limit))

        if mode in ("graph", "hybrid"):
            results.extend(self._graph_search(query, node_type, limit, target))

        if mode == "semantic":
            results.extend(self._semantic_search(query, node_type, limit))

        fused = self._rrf_fuse(results, limit)

        self._emit("search.completed", {
            "query": query, "mode": mode,
            "result_count": len(fused),
        })
        return [r.to_dict() for r in fused]

    def search_by_type(self, node_type: str, query: str = "",
                       limit: int = 50) -> list[dict]:
        """Search within a specific entity type."""
        if node_type not in ENTITY_TYPES:
            return []
        results = self._keyword_search(query or "*", node_type, limit)
        return [r.to_dict() for r in results[:limit]]

    def suggest(self, partial: str, limit: int = 10) -> list[dict]:
        """Auto-complete suggestions for partial queries."""
        try:
            from hydra.knowledge.wiki_store import WikiStore
            store = WikiStore(self._data_dir / "wiki")
            matches = []
            for page in store.iter_pages():
                slug = page.get("slug", "") if isinstance(page, dict) else str(page)
                title = page.get("title", slug) if isinstance(page, dict) else slug
                if partial.lower() in slug.lower() or partial.lower() in title.lower():
                    matches.append({"slug": slug, "title": title})
                    if len(matches) >= limit:
                        break
            return matches
        except (ImportError, Exception):
            return self._fallback_suggest(partial, limit)

    def get_facets(self, query: str = "") -> dict:
        """Get faceted counts for a query (by type, severity, target)."""
        results = self.search(query or "*", mode="keyword", limit=200)
        facets: dict[str, dict[str, int]] = {
            "by_type": {},
            "by_target": {},
        }
        for r in results:
            nt = r.get("node_type", "unknown")
            facets["by_type"][nt] = facets["by_type"].get(nt, 0) + 1
            tgt = r.get("metadata", {}).get("target", "")
            if tgt:
                facets["by_target"][tgt] = facets["by_target"].get(tgt, 0) + 1
        return facets

    def get_stats(self) -> dict[str, Any]:
        """Search service statistics."""
        return {
            "modes": list(SEARCH_MODES),
            "entity_types": list(ENTITY_TYPES),
            "mode_count": len(SEARCH_MODES),
        }

    # ── Search strategies ──

    def _keyword_search(self, query: str, node_type: str,
                        limit: int) -> list[SearchResult]:
        try:
            from hydra.knowledge.wiki_store import WikiStore
            store = WikiStore(self._data_dir / "wiki")
            hits = store.search(query, limit=limit)
            results = []
            for h in hits:
                slug = h.get("slug", "") if isinstance(h, dict) else str(h)
                score = h.get("score", 0.5) if isinstance(h, dict) else 0.5
                nt = h.get("type", "") if isinstance(h, dict) else ""
                title = h.get("title", slug) if isinstance(h, dict) else slug
                snippet = h.get("snippet", "") if isinstance(h, dict) else ""
                if node_type and nt and nt != node_type:
                    continue
                results.append(SearchResult(
                    slug=slug, title=title, score=score,
                    source="keyword", snippet=snippet, node_type=nt,
                ))
            return results
        except (ImportError, Exception):
            return self._fallback_keyword(query, node_type, limit)

    def _graph_search(self, query: str, node_type: str,
                      limit: int, target: str = "") -> list[SearchResult]:
        try:
            from hydra.knowledge.wiki_store import WikiStore
            from hydra.knowledge.graph import KnowledgeGraphIndex

            store = WikiStore(self._data_dir / "wiki")
            graph = KnowledgeGraphIndex(store)

            seed_results = store.search(query, limit=3)
            results = []
            seen = set()
            for seed in seed_results:
                seed_slug = seed.get("slug", "") if isinstance(seed, dict) else str(seed)
                if not seed_slug:
                    continue
                neighbors = graph.neighbors(seed_slug)
                for n in (neighbors if isinstance(neighbors, list) else []):
                    n_slug = n.get("slug", n) if isinstance(n, dict) else str(n)
                    if n_slug in seen:
                        continue
                    seen.add(n_slug)
                    nt = n.get("type", "") if isinstance(n, dict) else ""
                    if node_type and nt and nt != node_type:
                        continue
                    results.append(SearchResult(
                        slug=n_slug,
                        title=n.get("title", n_slug) if isinstance(n, dict) else n_slug,
                        score=0.3,
                        source="graph",
                        node_type=nt,
                    ))
                    if len(results) >= limit:
                        break
            return results
        except (ImportError, Exception):
            return []

    def _semantic_search(self, query: str, node_type: str,
                         limit: int) -> list[SearchResult]:
        return []

    # ── Fusion ──

    def _rrf_fuse(self, results: list[SearchResult],
                  limit: int, k: int = 60) -> list[SearchResult]:
        """Reciprocal Rank Fusion across search strategies."""
        by_source: dict[str, list[SearchResult]] = {}
        for r in results:
            by_source.setdefault(r.source, []).append(r)

        for source_list in by_source.values():
            source_list.sort(key=lambda x: x.score, reverse=True)

        scores: dict[str, float] = {}
        best: dict[str, SearchResult] = {}
        for source, items in by_source.items():
            for rank, item in enumerate(items):
                rrf_score = 1.0 / (k + rank + 1)
                slug = item.slug
                scores[slug] = scores.get(slug, 0.0) + rrf_score
                if slug not in best or item.score > best[slug].score:
                    best[slug] = item

        fused = []
        for slug in sorted(scores, key=scores.get, reverse=True)[:limit]:
            item = best[slug]
            item.score = scores[slug]
            fused.append(item)
        return fused

    # ── Fallbacks ──

    def _fallback_keyword(self, query: str, node_type: str,
                          limit: int) -> list[SearchResult]:
        try:
            from hydra.knowledge.wiki_store import WikiStore
            store = WikiStore()
            hits = store.recall(query, limit=limit)
            results = []
            for h in hits:
                slug = h.get("slug", "") if isinstance(h, dict) else str(h)
                if not slug:
                    continue
                results.append(SearchResult(
                    slug=slug, score=0.5, source="keyword",
                    title=h.get("title", slug) if isinstance(h, dict) else slug,
                ))
            return results
        except (ImportError, Exception):
            return []

    def _fallback_suggest(self, partial: str, limit: int) -> list[dict]:
        try:
            from hydra.knowledge.wiki_store import WikiStore
            store = WikiStore()
            hits = store.search(partial, limit=limit)
            return [
                {"slug": h.get("slug", "") if isinstance(h, dict) else str(h),
                 "title": h.get("title", "") if isinstance(h, dict) else str(h)}
                for h in hits
            ]
        except (ImportError, Exception):
            return []
