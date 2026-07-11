"""Ingest Service — multi-source knowledge ingestion into the wiki.

Wraps ReportIntelligencePipeline and provides source-specific adapters
for HackerOne reports, CVE/NVD, MITRE ATT&CK, GitHub advisories, and
generic blog/article content. Every source normalizes into the existing
ExtractedReport pipeline — no new page types are introduced.
"""

import json
import logging
from dataclasses import dataclass, field
from typing import Any

from hydra.services.base import BaseService

logger = logging.getLogger("hydra.services.ingest")

# Supported source types for the ingestor registry
SOURCE_TYPES = (
    "writeup", "hackerone", "medium", "blog", "github_advisory",
    "cve", "nvd", "mitre", "owasp", "vendor_advisory", "research_paper",
)


@dataclass
class IngestResult:
    """Outcome of a single ingestion operation."""
    slug: str = ""
    title: str = ""
    source_type: str = ""
    learning_score: int = 0
    vuln_class: str = ""
    report_path: str = ""
    intel_path: str = ""
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error

    def to_dict(self) -> dict[str, Any]:
        return {
            "slug": self.slug, "title": self.title,
            "source_type": self.source_type,
            "learning_score": self.learning_score,
            "vuln_class": self.vuln_class,
            "report_path": self.report_path,
            "intel_path": self.intel_path,
            "error": self.error,
        }


@dataclass
class IngestBatchResult:
    """Outcome of a batch ingestion."""
    total: int = 0
    succeeded: int = 0
    failed: int = 0
    results: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total, "succeeded": self.succeeded,
            "failed": self.failed, "results": self.results,
        }


class IngestService(BaseService):
    """Multi-source knowledge ingestion service.

    Normalizes content from any supported source into the existing
    ReportIntelligencePipeline, producing canonical report + intel pages.
    """

    def _pipeline(self):
        from hydra.knowledge.report_intel import ReportIntelligencePipeline
        return ReportIntelligencePipeline()

    def ingest_text(self, text: str, *, title: str = "", target: str = "",
                    source_url: str = "", source_type: str = "writeup") -> IngestResult:
        """Ingest raw text content."""
        try:
            from hydra.knowledge.report_intel import ReportSource
            src = ReportSource(
                text=text, title=title, target=target,
                source_url=source_url, source_type=source_type,
            )
            extracted = self._pipeline().ingest(src)
            result = IngestResult(
                slug=extracted.slug, title=extracted.title,
                source_type=source_type,
                learning_score=extracted.learning_score,
                vuln_class=extracted.vuln_class.value,
                report_path=extracted.report_path,
                intel_path=extracted.intel_path,
            )
            self._emit("ingest.completed", {
                "slug": result.slug, "source_type": source_type,
                "learning_score": result.learning_score,
            })
            return result
        except Exception as e:
            logger.error("ingest_text failed: %s", e)
            return IngestResult(error=str(e))

    def ingest_file(self, path: str, *, title: str = "", target: str = "",
                    source_url: str = "", source_type: str = "writeup") -> IngestResult:
        """Ingest a local file."""
        try:
            from hydra.knowledge.report_intel import ReportSource
            src = ReportSource(
                path=path, title=title, target=target,
                source_url=source_url, source_type=source_type,
            )
            extracted = self._pipeline().ingest(src)
            result = IngestResult(
                slug=extracted.slug, title=extracted.title,
                source_type=source_type,
                learning_score=extracted.learning_score,
                vuln_class=extracted.vuln_class.value,
                report_path=extracted.report_path,
                intel_path=extracted.intel_path,
            )
            self._emit("ingest.completed", {
                "slug": result.slug, "source_type": source_type,
                "learning_score": result.learning_score,
            })
            return result
        except Exception as e:
            logger.error("ingest_file failed: %s", e)
            return IngestResult(error=str(e))

    def ingest_batch(self, items: list[dict]) -> IngestBatchResult:
        """Ingest multiple items. Each dict needs at least 'text' or 'path'."""
        batch = IngestBatchResult(total=len(items))
        for item in items:
            if "text" in item:
                r = self.ingest_text(
                    item["text"], title=item.get("title", ""),
                    target=item.get("target", ""),
                    source_url=item.get("source_url", ""),
                    source_type=item.get("source_type", "writeup"),
                )
            elif "path" in item:
                r = self.ingest_file(
                    item["path"], title=item.get("title", ""),
                    target=item.get("target", ""),
                    source_url=item.get("source_url", ""),
                    source_type=item.get("source_type", "writeup"),
                )
            else:
                r = IngestResult(error="item needs 'text' or 'path'")
            if r.ok:
                batch.succeeded += 1
            else:
                batch.failed += 1
            batch.results.append(r.to_dict())
        self._emit("ingest.batch_completed", {
            "total": batch.total, "succeeded": batch.succeeded,
            "failed": batch.failed,
        })
        return batch

    def ingest_hackerone(self, report_json: str) -> IngestResult:
        """Ingest a HackerOne disclosed report (JSON format)."""
        try:
            data = json.loads(report_json)
            text = self._normalize_hackerone(data)
            title = data.get("title", "HackerOne Report")
            target = data.get("team", {}).get("handle", "")
            url = data.get("url", "")
            return self.ingest_text(
                text, title=title, target=target,
                source_url=url, source_type="hackerone",
            )
        except Exception as e:
            return IngestResult(error=f"HackerOne parse: {e}")

    def ingest_cve(self, cve_json: str) -> IngestResult:
        """Ingest a CVE/NVD entry (JSON format)."""
        try:
            data = json.loads(cve_json)
            text = self._normalize_cve(data)
            cve_id = data.get("id", data.get("cve", {}).get("id", "CVE-unknown"))
            return self.ingest_text(
                text, title=cve_id, source_type="cve",
                source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            )
        except Exception as e:
            return IngestResult(error=f"CVE parse: {e}")

    def ingest_github_advisory(self, advisory_json: str) -> IngestResult:
        """Ingest a GitHub Security Advisory (JSON format)."""
        try:
            data = json.loads(advisory_json)
            text = self._normalize_github_advisory(data)
            ghsa_id = data.get("ghsa_id", data.get("id", "GHSA-unknown"))
            url = data.get("html_url", "")
            return self.ingest_text(
                text, title=ghsa_id, source_url=url,
                source_type="github_advisory",
            )
        except Exception as e:
            return IngestResult(error=f"GitHub advisory parse: {e}")

    def list_sources(self) -> list[str]:
        """Return supported source types."""
        return list(SOURCE_TYPES)

    def get_stats(self) -> dict[str, Any]:
        """Return ingestion statistics from the wiki."""
        try:
            from hydra.knowledge.wiki_store import WikiStore
            from hydra.knowledge.schema import NodeType
            store = WikiStore()
            reports = list(store.iter_pages(NodeType.REPORT))
            intel = list(store.iter_pages(NodeType.INTEL))
            scores = [
                p.meta.get("learning_score", 0) for p in reports
                if p.meta.get("learning_score")
            ]
            return {
                "reports": len(reports),
                "intel": len(intel),
                "avg_learning_score": round(sum(scores) / max(len(scores), 1), 1),
                "max_learning_score": max(scores) if scores else 0,
                "sources": list(SOURCE_TYPES),
            }
        except Exception:
            return {"reports": 0, "intel": 0, "avg_learning_score": 0,
                    "max_learning_score": 0, "sources": list(SOURCE_TYPES)}

    # ── Normalizers ──

    def _normalize_hackerone(self, data: dict) -> str:
        parts = []
        parts.append(f"# {data.get('title', 'Untitled')}\n")
        if data.get("vulnerability_information"):
            parts.append(f"## Vulnerability Details\n{data['vulnerability_information']}\n")
        if data.get("weakness"):
            w = data["weakness"]
            parts.append(f"## Weakness\n- Name: {w.get('name', 'unknown')}\n")
            if w.get("external_id"):
                parts.append(f"- CWE: {w['external_id']}\n")
        if data.get("severity"):
            s = data["severity"]
            parts.append(f"## Severity\n- Rating: {s.get('rating', 'unknown')}\n")
            if s.get("score"):
                parts.append(f"- CVSS: {s['score']}\n")
        if data.get("impact"):
            parts.append(f"## Impact\n{data['impact']}\n")
        if data.get("structured_scope"):
            scope = data["structured_scope"]
            parts.append(f"## Scope\n- Asset: {scope.get('asset_identifier', 'unknown')}\n")
            parts.append(f"- Type: {scope.get('asset_type', 'unknown')}\n")
        return "\n".join(parts)

    def _normalize_cve(self, data: dict) -> str:
        parts = []
        cve_id = data.get("id", data.get("cve", {}).get("id", "CVE-unknown"))
        parts.append(f"# {cve_id}\n")
        desc_data = data.get("descriptions", data.get("cve", {}).get("description", {}).get("description_data", []))
        if isinstance(desc_data, list):
            for d in desc_data:
                val = d.get("value", "") if isinstance(d, dict) else str(d)
                if val:
                    parts.append(f"## Description\n{val}\n")
                    break
        metrics = data.get("metrics", data.get("impact", {}))
        if metrics:
            parts.append(f"## Metrics\n{json.dumps(metrics, indent=2)}\n")
        refs = data.get("references", [])
        if refs:
            parts.append("## References\n")
            for ref in refs[:10]:
                url = ref.get("url", str(ref)) if isinstance(ref, dict) else str(ref)
                parts.append(f"- {url}\n")
        cwes = data.get("weaknesses", [])
        if cwes:
            parts.append("## Weaknesses\n")
            for cwe in cwes[:5]:
                desc = cwe.get("description", [])
                if desc:
                    val = desc[0].get("value", "") if isinstance(desc[0], dict) else str(desc[0])
                    parts.append(f"- {val}\n")
        return "\n".join(parts)

    def _normalize_github_advisory(self, data: dict) -> str:
        parts = []
        parts.append(f"# {data.get('summary', data.get('ghsa_id', 'Advisory'))}\n")
        if data.get("description"):
            parts.append(f"## Description\n{data['description']}\n")
        if data.get("severity"):
            parts.append(f"## Severity\n- {data['severity']}\n")
        if data.get("cvss", {}).get("score"):
            parts.append(f"- CVSS: {data['cvss']['score']}\n")
        if data.get("cve_id"):
            parts.append(f"## CVE\n- {data['cve_id']}\n")
        if data.get("cwes"):
            parts.append("## CWEs\n")
            for cwe in data["cwes"][:5]:
                cid = cwe.get("cwe_id", str(cwe)) if isinstance(cwe, dict) else str(cwe)
                parts.append(f"- {cid}\n")
        vulns = data.get("vulnerabilities", [])
        if vulns:
            parts.append("## Affected\n")
            for v in vulns[:10]:
                pkg = v.get("package", {})
                parts.append(f"- {pkg.get('ecosystem', '?')}/{pkg.get('name', '?')}\n")
        return "\n".join(parts)
