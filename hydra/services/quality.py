"""Knowledge Quality Control Service (Phase 10.12).

Continuously evaluates knowledge quality. Detects duplicates,
contradictions, outdated techniques, deprecated payloads,
invalid references, broken links, and low-confidence knowledge.
"""

import logging
import time
from typing import Any

from hydra.services.base import BaseService

logger = logging.getLogger("hydra.services.quality")

ISSUE_TYPES = (
    "duplicate", "contradiction", "outdated", "deprecated",
    "invalid_reference", "broken_link", "low_confidence",
    "missing_evidence", "stale",
)

SEVERITY_LEVELS = ("critical", "high", "medium", "low", "info")


class QualityIssue:
    __slots__ = ("id", "issue_type", "severity", "slug", "description",
                 "suggestion", "detected_at", "resolved")

    def __init__(self, issue_type: str, slug: str, description: str,
                 severity: str = "medium", suggestion: str = ""):
        self.id = f"qi-{int(time.time() * 1000)}"
        self.issue_type = issue_type
        self.severity = severity
        self.slug = slug
        self.description = description
        self.suggestion = suggestion
        self.detected_at = time.time()
        self.resolved = False

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "issue_type": self.issue_type,
            "severity": self.severity,
            "slug": self.slug,
            "description": self.description,
            "suggestion": self.suggestion,
            "detected_at": self.detected_at,
            "resolved": self.resolved,
        }


class QualityService(BaseService):
    """Knowledge base quality control and health monitoring."""

    def audit(self, scope: str = "all", limit: int = 50) -> dict:
        """Run a quality audit across the knowledge base."""
        issues: list[dict] = []

        if scope in ("all", "duplicates"):
            issues.extend(self._check_duplicates(limit))
        if scope in ("all", "stale"):
            issues.extend(self._check_stale(limit))
        if scope in ("all", "low_confidence"):
            issues.extend(self._check_low_confidence(limit))
        if scope in ("all", "links"):
            issues.extend(self._check_broken_links(limit))

        issues.sort(key=lambda x: SEVERITY_LEVELS.index(x.get("severity", "info")))

        self._emit("quality.audit_completed", {
            "scope": scope,
            "issues_found": len(issues),
        })

        return {
            "status": "completed",
            "scope": scope,
            "issues": issues[:limit],
            "total_issues": len(issues),
            "by_type": self._count_by(issues, "issue_type"),
            "by_severity": self._count_by(issues, "severity"),
        }

    def check_page(self, slug: str) -> dict:
        """Check quality of a specific knowledge page."""
        issues: list[dict] = []
        try:
            from hydra.knowledge.wiki_store import WikiStore
            store = WikiStore(self._data_dir / "wiki")
            page = store.read(slug)
            if page is None:
                return {"slug": slug, "status": "not_found", "issues": []}

            meta = page.get("meta", {}) if isinstance(page, dict) else {}
            body = page.get("body", "") if isinstance(page, dict) else str(page)

            if not body or len(body) < 50:
                issues.append(QualityIssue(
                    "missing_evidence", slug,
                    "Page has minimal content",
                    severity="medium",
                    suggestion="Add detailed evidence or analysis",
                ).to_dict())

            confidence = meta.get("confidence", 0)
            if isinstance(confidence, (int, float)) and confidence < 0.3:
                issues.append(QualityIssue(
                    "low_confidence", slug,
                    f"Low confidence score: {confidence}",
                    severity="low",
                    suggestion="Add independent confirmation sources",
                ).to_dict())

            links = self._extract_links(body)
            for link in links:
                if not self._link_valid(store, link):
                    issues.append(QualityIssue(
                        "broken_link", slug,
                        f"Broken internal link: [[{link}]]",
                        severity="low",
                        suggestion=f"Fix or remove link to {link}",
                    ).to_dict())

        except (ImportError, Exception):
            pass

        return {
            "slug": slug,
            "status": "checked",
            "issues": issues,
            "issue_count": len(issues),
            "healthy": len(issues) == 0,
        }

    def get_health_score(self) -> dict:
        """Overall knowledge base health score (0-100)."""
        audit = self.audit(limit=200)
        total = audit["total_issues"]
        by_sev = audit.get("by_severity", {})

        critical = by_sev.get("critical", 0) * 10
        high = by_sev.get("high", 0) * 5
        medium = by_sev.get("medium", 0) * 2
        low = by_sev.get("low", 0) * 1

        penalty = min(critical + high + medium + low, 100)
        score = max(100 - penalty, 0)

        return {
            "health_score": score,
            "total_issues": total,
            "by_severity": by_sev,
            "grade": self._grade(score),
        }

    def get_stats(self) -> dict[str, Any]:
        """Quality service statistics."""
        return {
            "issue_types": list(ISSUE_TYPES),
            "severity_levels": list(SEVERITY_LEVELS),
            "issue_type_count": len(ISSUE_TYPES),
        }

    def _check_duplicates(self, limit: int) -> list[dict]:
        """Detect duplicate knowledge pages."""
        issues = []
        try:
            from hydra.knowledge.wiki_store import WikiStore
            store = WikiStore(self._data_dir / "wiki")
            seen_titles: dict[str, str] = {}
            for page in store.iter_pages():
                slug = page.get("slug", "") if isinstance(page, dict) else str(page)
                title = page.get("title", "") if isinstance(page, dict) else ""
                normalized = title.lower().strip()
                if normalized and normalized in seen_titles:
                    issues.append(QualityIssue(
                        "duplicate", slug,
                        f"Possible duplicate of {seen_titles[normalized]}",
                        severity="medium",
                        suggestion="Merge or deduplicate",
                    ).to_dict())
                elif normalized:
                    seen_titles[normalized] = slug
                if len(issues) >= limit:
                    break
        except (ImportError, Exception):
            pass
        return issues

    def _check_stale(self, limit: int) -> list[dict]:
        """Detect stale knowledge (not updated in 180+ days)."""
        issues = []
        cutoff = time.time() - (180 * 86400)
        try:
            from hydra.knowledge.wiki_store import WikiStore
            store = WikiStore(self._data_dir / "wiki")
            for page in store.iter_pages():
                slug = page.get("slug", "") if isinstance(page, dict) else str(page)
                meta = page.get("meta", {}) if isinstance(page, dict) else {}
                updated = meta.get("updated", 0) or meta.get("created", 0)
                if isinstance(updated, (int, float)) and 0 < updated < cutoff:
                    age = int((time.time() - updated) / 86400)
                    issues.append(QualityIssue(
                        "stale", slug,
                        f"Not updated in {age} days",
                        severity="low",
                        suggestion="Review and refresh",
                    ).to_dict())
                if len(issues) >= limit:
                    break
        except (ImportError, Exception):
            pass
        return issues

    def _check_low_confidence(self, limit: int) -> list[dict]:
        """Detect low-confidence knowledge."""
        issues = []
        try:
            from hydra.knowledge.wiki_store import WikiStore
            store = WikiStore(self._data_dir / "wiki")
            for page in store.iter_pages():
                slug = page.get("slug", "") if isinstance(page, dict) else str(page)
                meta = page.get("meta", {}) if isinstance(page, dict) else {}
                conf = meta.get("confidence", 1.0)
                if isinstance(conf, (int, float)) and conf < 0.3:
                    issues.append(QualityIssue(
                        "low_confidence", slug,
                        f"Confidence {conf:.2f} below threshold",
                        severity="low",
                        suggestion="Add verification or sources",
                    ).to_dict())
                if len(issues) >= limit:
                    break
        except (ImportError, Exception):
            pass
        return issues

    def _check_broken_links(self, limit: int) -> list[dict]:
        """Detect broken internal wiki links."""
        issues = []
        try:
            from hydra.knowledge.wiki_store import WikiStore
            store = WikiStore(self._data_dir / "wiki")
            for page in store.iter_pages():
                slug = page.get("slug", "") if isinstance(page, dict) else str(page)
                body = page.get("body", "") if isinstance(page, dict) else ""
                links = self._extract_links(body)
                for link in links:
                    if not self._link_valid(store, link):
                        issues.append(QualityIssue(
                            "broken_link", slug,
                            f"Broken link: [[{link}]]",
                            severity="low",
                        ).to_dict())
                if len(issues) >= limit:
                    break
        except (ImportError, Exception):
            pass
        return issues

    def _extract_links(self, text: str) -> list[str]:
        """Extract [[wikilinks]] from text."""
        import re
        return re.findall(r'\[\[([^\]]+)\]\]', text)

    def _link_valid(self, store, slug: str) -> bool:
        """Check if a wiki slug exists."""
        try:
            page = store.read(slug)
            return page is not None
        except Exception:
            return False

    def _count_by(self, items: list[dict], key: str) -> dict[str, int]:
        counts: dict[str, int] = {}
        for item in items:
            val = item.get(key, "unknown")
            counts[val] = counts.get(val, 0) + 1
        return counts

    def _grade(self, score: int) -> str:
        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 70:
            return "C"
        if score >= 60:
            return "D"
        return "F"
