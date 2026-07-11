"""Report Store Service — structured queries over report/intel wiki pages.

Provides filtering, aggregation, and confidence tracking over the
ingested knowledge base. All data lives in the canonical wiki —
this service is a query layer, not a separate store.
"""

import logging
from dataclasses import dataclass
from typing import Any

from hydra.services.base import BaseService

logger = logging.getLogger("hydra.services.report_store")


@dataclass
class ReportEntry:
    """Lightweight report summary for listings."""
    slug: str = ""
    title: str = ""
    target: str = ""
    vuln_class: str = ""
    learning_score: int = 0
    source_type: str = ""
    source_url: str = ""
    created: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "slug": self.slug, "title": self.title,
            "target": self.target, "vuln_class": self.vuln_class,
            "learning_score": self.learning_score,
            "source_type": self.source_type,
            "source_url": self.source_url,
            "created": self.created,
        }


class ReportStoreService(BaseService):
    """Structured queries over ingested reports and intel."""

    def _store(self):
        from hydra.knowledge.wiki_store import WikiStore
        return WikiStore()

    def list_reports(self, *, target: str = "", vuln_class: str = "",
                     min_score: int = 0, source_type: str = "",
                     limit: int = 50) -> list[dict]:
        """List reports with optional filters."""
        try:
            from hydra.knowledge.schema import NodeType
            store = self._store()
            pages = list(store.iter_pages(NodeType.REPORT))
            entries = []
            for p in pages:
                meta = p.meta
                score = meta.get("learning_score", 0)
                if score < min_score:
                    continue
                p_target = meta.get("target", "")
                if target and target.lower() not in p_target.lower():
                    continue
                p_vuln = meta.get("vuln_class", "")
                if vuln_class and vuln_class.lower() != p_vuln.lower():
                    continue
                p_src = meta.get("source_type", "")
                if source_type and source_type.lower() != p_src.lower():
                    continue
                entries.append(ReportEntry(
                    slug=p.slug,
                    title=meta.get("title", p.slug),
                    target=p_target,
                    vuln_class=p_vuln,
                    learning_score=score,
                    source_type=p_src,
                    source_url=meta.get("source_url", ""),
                    created=meta.get("created", ""),
                ).to_dict())
            entries.sort(key=lambda e: e["learning_score"], reverse=True)
            return entries[:limit]
        except Exception as e:
            logger.error("list_reports failed: %s", e)
            return []

    def list_intel(self, *, target: str = "", vuln_class: str = "",
                   limit: int = 50) -> list[dict]:
        """List intel pages with optional filters."""
        try:
            from hydra.knowledge.schema import NodeType
            store = self._store()
            pages = list(store.iter_pages(NodeType.INTEL))
            entries = []
            for p in pages:
                meta = p.meta
                p_target = meta.get("target", "")
                if target and target.lower() not in p_target.lower():
                    continue
                p_vuln = meta.get("vuln_class", "")
                if vuln_class and vuln_class.lower() != p_vuln.lower():
                    continue
                entries.append({
                    "slug": p.slug,
                    "title": meta.get("title", p.slug),
                    "target": p_target,
                    "vuln_class": p_vuln,
                    "created": meta.get("created", ""),
                })
            return entries[:limit]
        except Exception as e:
            logger.error("list_intel failed: %s", e)
            return []

    def get_report(self, slug: str) -> dict | None:
        """Get full report content and metadata."""
        try:
            store = self._store()
            page = store.read(slug)
            if page is None:
                return None
            return {
                "slug": page.slug,
                "meta": dict(page.meta),
                "body": page.body,
                "links": page.links,
            }
        except Exception:
            return None

    def search(self, query: str, *, limit: int = 20) -> list[dict]:
        """Full-text search across reports and intel."""
        try:
            store = self._store()
            results = store.search(query, limit=limit)
            return [
                {
                    "slug": r.get("slug", ""),
                    "title": r.get("title", ""),
                    "score": r.get("score", 0),
                    "snippet": r.get("snippet", ""),
                }
                for r in results
            ]
        except Exception:
            return []

    def aggregate_by_vuln_class(self) -> list[dict]:
        """Aggregate reports by vulnerability class."""
        try:
            from hydra.knowledge.schema import NodeType
            store = self._store()
            pages = list(store.iter_pages(NodeType.REPORT))
            counts: dict[str, dict] = {}
            for p in pages:
                vc = p.meta.get("vuln_class", "unknown")
                if vc not in counts:
                    counts[vc] = {"vuln_class": vc, "count": 0,
                                  "total_score": 0, "max_score": 0}
                counts[vc]["count"] += 1
                score = p.meta.get("learning_score", 0)
                counts[vc]["total_score"] += score
                counts[vc]["max_score"] = max(counts[vc]["max_score"], score)
            result = list(counts.values())
            for r in result:
                r["avg_score"] = round(r["total_score"] / max(r["count"], 1), 1)
            result.sort(key=lambda x: x["count"], reverse=True)
            return result
        except Exception:
            return []

    def aggregate_by_target(self) -> list[dict]:
        """Aggregate reports by target."""
        try:
            from hydra.knowledge.schema import NodeType
            store = self._store()
            pages = list(store.iter_pages(NodeType.REPORT))
            counts: dict[str, dict] = {}
            for p in pages:
                tgt = p.meta.get("target", "unknown")
                if tgt not in counts:
                    counts[tgt] = {"target": tgt, "count": 0,
                                   "vuln_classes": set(), "max_score": 0}
                counts[tgt]["count"] += 1
                vc = p.meta.get("vuln_class", "")
                if vc:
                    counts[tgt]["vuln_classes"].add(vc)
                score = p.meta.get("learning_score", 0)
                counts[tgt]["max_score"] = max(counts[tgt]["max_score"], score)
            result = []
            for t in counts.values():
                result.append({
                    "target": t["target"],
                    "count": t["count"],
                    "vuln_classes": sorted(t["vuln_classes"]),
                    "max_score": t["max_score"],
                })
            result.sort(key=lambda x: x["count"], reverse=True)
            return result
        except Exception:
            return []

    def get_stats(self) -> dict[str, Any]:
        """Overall report store statistics."""
        try:
            from hydra.knowledge.schema import NodeType
            store = self._store()
            reports = list(store.iter_pages(NodeType.REPORT))
            intel = list(store.iter_pages(NodeType.INTEL))
            scores = [p.meta.get("learning_score", 0) for p in reports]
            vuln_classes = set(p.meta.get("vuln_class", "") for p in reports) - {""}
            targets = set(p.meta.get("target", "") for p in reports) - {""}
            return {
                "total_reports": len(reports),
                "total_intel": len(intel),
                "unique_vuln_classes": len(vuln_classes),
                "unique_targets": len(targets),
                "avg_learning_score": round(sum(scores) / max(len(scores), 1), 1),
                "max_learning_score": max(scores) if scores else 0,
                "score_distribution": self._score_distribution(scores),
            }
        except Exception:
            return {"total_reports": 0, "total_intel": 0}

    def get_high_value(self, *, min_score: int = 7, limit: int = 20) -> list[dict]:
        """Get high-value reports (learning_score >= min_score)."""
        return self.list_reports(min_score=min_score, limit=limit)

    def get_related(self, slug: str, *, limit: int = 10) -> list[dict]:
        """Get reports related to the given slug via wiki links."""
        try:
            store = self._store()
            page = store.read(slug)
            if page is None:
                return []
            related = []
            for link in page.links[:limit]:
                linked = store.read(link)
                if linked:
                    related.append({
                        "slug": linked.slug,
                        "title": linked.meta.get("title", linked.slug),
                        "type": linked.meta.get("type", ""),
                    })
            return related
        except Exception:
            return []

    def _score_distribution(self, scores: list[int]) -> dict[str, int]:
        dist = {"low_1_3": 0, "mid_4_6": 0, "high_7_10": 0}
        for s in scores:
            if s <= 3:
                dist["low_1_3"] += 1
            elif s <= 6:
                dist["mid_4_6"] += 1
            else:
                dist["high_7_10"] += 1
        return dist
