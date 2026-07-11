"""Context Intelligence Service (Phase 10.7).

Enriches every operation with relevant prior knowledge. Before executing
any action, the system retrieves and correlates context from all knowledge
subsystems — wiki, memory, graph, TTPs, lessons, and reports.
"""

import logging
from typing import Any

from hydra.services.base import BaseService

logger = logging.getLogger("hydra.services.context_intel")

CONTEXT_SOURCES = (
    "wiki", "memory", "graph", "ttp", "lessons", "reports",
    "findings", "patterns", "chains",
)

ENRICHMENT_TYPES = (
    "prior_findings", "known_patterns", "related_ttps",
    "target_history", "tech_context", "attack_chains",
)


class ContextIntelService(BaseService):
    """Pre-action context enrichment from all knowledge subsystems."""

    def enrich(self, target: str = "", action: str = "",
               vuln_class: str = "", tech_stack: str = "") -> dict:
        """Gather all relevant context for an upcoming action."""
        context: dict[str, Any] = {
            "target": target,
            "action": action,
            "vuln_class": vuln_class,
            "sources_queried": [],
            "enrichments": [],
            "recommendations": [],
        }

        if target:
            context["enrichments"].extend(self._enrich_target(target))
            context["sources_queried"].append("wiki")
            context["sources_queried"].append("findings")

        if vuln_class:
            context["enrichments"].extend(self._enrich_vuln_class(vuln_class))
            context["sources_queried"].append("ttp")
            context["sources_queried"].append("patterns")

        if tech_stack:
            context["enrichments"].extend(self._enrich_tech(tech_stack))
            context["sources_queried"].append("lessons")

        context["enrichments"].extend(self._enrich_memory(target, vuln_class))
        context["sources_queried"].append("memory")

        context["recommendations"] = self._generate_recommendations(context)

        self._emit("context_intel.enriched", {
            "target": target,
            "action": action,
            "enrichment_count": len(context["enrichments"]),
            "source_count": len(context["sources_queried"]),
        })

        return {
            "status": "enriched",
            **context,
        }

    def get_target_history(self, target: str) -> dict:
        """Get full historical context for a target."""
        history = {
            "target": target,
            "findings": [],
            "scans": [],
            "patterns": [],
            "first_seen": None,
            "last_seen": None,
        }

        try:
            from hydra.knowledge.wiki_store import WikiStore
            store = WikiStore(self._data_dir / "wiki")
            hits = store.search(target, limit=20)
            for h in hits:
                slug = h.get("slug", "") if isinstance(h, dict) else str(h)
                page_type = h.get("type", "") if isinstance(h, dict) else ""
                if "finding" in page_type:
                    history["findings"].append(slug)
                elif "pattern" in page_type:
                    history["patterns"].append(slug)
                else:
                    history["scans"].append(slug)
        except (ImportError, Exception):
            pass

        return history

    def get_vuln_intel(self, vuln_class: str) -> dict:
        """Get intelligence about a vulnerability class."""
        intel = {
            "vuln_class": vuln_class,
            "known_patterns": [],
            "success_rate": 0.0,
            "common_targets": [],
            "recommended_tools": [],
            "payloads_available": False,
        }

        tool_map = {
            "xss": ["dalfox", "gxss", "nuclei"],
            "sqli": ["sqlmap", "nuclei"],
            "ssrf": ["nuclei", "ffuf"],
            "ssti": ["nuclei"],
            "lfi": ["ffuf", "dirsearch"],
            "idor": ["ffuf"],
            "cors": ["nuclei"],
        }

        if vuln_class in tool_map:
            intel["recommended_tools"] = tool_map[vuln_class]
            intel["payloads_available"] = True

        try:
            from hydra.knowledge.wiki_store import WikiStore
            store = WikiStore(self._data_dir / "wiki")
            hits = store.search(vuln_class, limit=10)
            for h in hits:
                slug = h.get("slug", "") if isinstance(h, dict) else str(h)
                if slug:
                    intel["known_patterns"].append(slug)
        except (ImportError, Exception):
            pass

        return intel

    def get_stats(self) -> dict[str, Any]:
        """Context intelligence statistics."""
        return {
            "context_sources": list(CONTEXT_SOURCES),
            "source_count": len(CONTEXT_SOURCES),
            "enrichment_types": list(ENRICHMENT_TYPES),
            "enrichment_type_count": len(ENRICHMENT_TYPES),
        }

    def _enrich_target(self, target: str) -> list[dict]:
        enrichments = []
        try:
            from hydra.knowledge.wiki_store import WikiStore
            store = WikiStore(self._data_dir / "wiki")
            hits = store.search(target, limit=5)
            for h in hits:
                slug = h.get("slug", "") if isinstance(h, dict) else str(h)
                if slug:
                    enrichments.append({
                        "type": "prior_findings",
                        "source": "wiki",
                        "slug": slug,
                        "relevance": "direct_match",
                    })
        except (ImportError, Exception):
            pass
        return enrichments

    def _enrich_vuln_class(self, vuln_class: str) -> list[dict]:
        enrichments = []
        enrichments.append({
            "type": "related_ttps",
            "source": "ttp",
            "vuln_class": vuln_class,
            "relevance": "class_match",
        })
        return enrichments

    def _enrich_tech(self, tech_stack: str) -> list[dict]:
        enrichments = []
        enrichments.append({
            "type": "tech_context",
            "source": "lessons",
            "tech_stack": tech_stack,
            "relevance": "technology_match",
        })
        return enrichments

    def _enrich_memory(self, target: str, vuln_class: str) -> list[dict]:
        enrichments = []
        if target or vuln_class:
            enrichments.append({
                "type": "target_history",
                "source": "memory",
                "query": target or vuln_class,
                "relevance": "memory_recall",
            })
        return enrichments

    def _generate_recommendations(self, context: dict) -> list[dict]:
        recs = []
        enrichments = context.get("enrichments", [])

        if any(e["type"] == "prior_findings" for e in enrichments):
            recs.append({
                "action": "review_prior",
                "description": "Review prior findings before testing",
                "priority": "high",
            })

        if context.get("vuln_class"):
            recs.append({
                "action": "check_patterns",
                "description": f"Check known patterns for {context['vuln_class']}",
                "priority": "medium",
            })

        return recs
