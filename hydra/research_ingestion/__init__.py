"""
╔══════════════════════════════════════════════════════════════╗
║  Research Knowledge Ingestion Engine                         ║
║  Transforms security research → exploit intelligence →       ║
║  reasoning heuristics → reusable skills                      ║
╚══════════════════════════════════════════════════════════════╝
"""

import json
import logging
import re
import time
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger("hydra.research_ingestion")


@dataclass
class ResearchSource:
    """A source of security research."""
    source_type: str              # hackerone, bugcrowd, cve, github_poc, writeup, conference
    url: str = ""
    title: str = ""
    content: str = ""
    author: str = ""
    date: str = ""
    tags: List[str] = field(default_factory=list)
    ingested_at: float = field(default_factory=time.time)


@dataclass
class ExtractedMethodology:
    """A methodology extracted from research."""
    id: str = ""
    title: str = ""
    attack_vector: str = ""
    steps: List[str] = field(default_factory=list)
    preconditions: List[str] = field(default_factory=list)
    payloads: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    bypass_techniques: List[str] = field(default_factory=list)
    severity: str = "medium"
    source: str = ""
    confidence: float = 0.5


@dataclass
class ExploitPattern:
    """A reusable exploit pattern learned from research."""
    id: str = ""
    pattern_type: str = ""
    description: str = ""
    regex_indicators: List[str] = field(default_factory=list)
    test_payloads: List[str] = field(default_factory=list)
    validation_checks: List[str] = field(default_factory=list)
    affected_technologies: List[str] = field(default_factory=list)
    cwe: str = ""
    cvss_range: str = ""
    source_count: int = 0


# ── Extraction Patterns ──────────────────────

VULN_TYPE_PATTERNS = {
    "xss": [r"cross.?site.?script", r"\bxss\b", r"reflected.?xss", r"stored.?xss", r"dom.?xss"],
    "sqli": [r"sql.?inject", r"\bsqli\b", r"union.?select", r"blind.?sql"],
    "ssrf": [r"server.?side.?request", r"\bssrf\b", r"internal.?request"],
    "idor": [r"insecure.?direct.?object", r"\bidor\b", r"broken.?access"],
    "rce": [r"remote.?code.?exec", r"\brce\b", r"command.?inject"],
    "auth_bypass": [r"auth(entication)?.?bypass", r"jwt.?bypass", r"session.?fixation"],
    "ssrf": [r"server.?side.?request", r"\bssrf\b"],
    "ssti": [r"server.?side.?template", r"\bssti\b", r"template.?inject"],
    "csrf": [r"cross.?site.?request.?forg", r"\bcsrf\b"],
    "xxe": [r"xml.?external.?entity", r"\bxxe\b"],
    "deserialization": [r"deserializ", r"unserialize", r"pickle", r"java\.io"],
    "path_traversal": [r"path.?travers", r"directory.?travers", r"local.?file.?incl", r"\blfi\b"],
    "open_redirect": [r"open.?redirect", r"url.?redirect"],
    "race_condition": [r"race.?condition", r"toctou", r"concurrency"],
}

PAYLOAD_EXTRACTION_PATTERNS = [
    r'(?:payload|vector|poc|input)\s*[:=]\s*["\'](.+?)["\']',
    r'(?:curl|wget|http)\s+.*?(?:[\'"](https?://\S+)["\'])',
    r'```(?:http|bash|sh|curl)?\s*\n(.+?)\n```',
]

SEVERITY_PATTERNS = {
    "critical": [r"\bcritical\b", r"cvss.{0,10}9\.\d", r"\brce\b", r"remote.?code"],
    "high": [r"\bhigh\b", r"cvss.{0,10}[7-8]\.\d", r"account.?takeover", r"\bato\b"],
    "medium": [r"\bmedium\b", r"cvss.{0,10}[4-6]\.\d"],
    "low": [r"\blow\b", r"cvss.{0,10}[1-3]\.\d", r"informational"],
}


class ResearchIngestionEngine:
    """
    Continuous autonomous research ingestion engine.

    Transforms:
      research → exploit intelligence → reasoning heuristics → reusable skills

    Sources:
      - HackerOne reports and disclosures
      - Bugcrowd disclosures
      - CVEs and NVD entries
      - GitHub PoCs and exploits
      - Security blog writeups
      - Conference talks and papers
      - OWASP research
      - Exploit databases
    """

    def __init__(self):
        self._sources: List[ResearchSource] = []
        self._methodologies: List[ExtractedMethodology] = []
        self._patterns: Dict[str, ExploitPattern] = {}
        self._ingestion_stats: Dict[str, int] = {}

    def ingest(self, source: ResearchSource) -> Dict[str, Any]:
        """Ingest a research source and extract intelligence."""
        self._sources.append(source)
        self._ingestion_stats[source.source_type] = (
            self._ingestion_stats.get(source.source_type, 0) + 1
        )

        results = {
            "source": source.title,
            "methodologies": [],
            "patterns": [],
            "payloads": [],
        }

        # Extract vulnerability type
        vuln_types = self._identify_vuln_types(source.content)

        # Extract methodology
        methodology = self._extract_methodology(source)
        if methodology:
            self._methodologies.append(methodology)
            results["methodologies"].append(methodology.title)

        # Extract payloads
        payloads = self._extract_payloads(source.content)
        results["payloads"] = payloads

        # Extract patterns
        for vtype in vuln_types:
            pattern = self._extract_pattern(source, vtype, payloads)
            if pattern:
                key = f"{vtype}:{pattern.description[:50]}"
                if key in self._patterns:
                    self._patterns[key].source_count += 1
                else:
                    self._patterns[key] = pattern
                results["patterns"].append(vtype)

        logger.info(
            f"📚 Ingested: {source.title} — "
            f"{len(vuln_types)} vuln types, {len(payloads)} payloads"
        )
        return results

    def _identify_vuln_types(self, content: str) -> List[str]:
        content_lower = content.lower()
        found = []
        for vtype, patterns in VULN_TYPE_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, content_lower):
                    found.append(vtype)
                    break
        return found

    def _extract_methodology(self, source: ResearchSource) -> Optional[ExtractedMethodology]:
        content = source.content
        if not content or len(content) < 100:
            return None

        # Extract steps (numbered lists, bullet points)
        steps = []
        step_patterns = [
            r'(?:^|\n)\s*\d+[\.\)]\s*(.+)',
            r'(?:^|\n)\s*[-*]\s*(.+)',
            r'(?:step|phase)\s*\d+\s*[:\.]\s*(.+)',
        ]
        for pattern in step_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
            steps.extend(matches[:10])

        if not steps:
            return None

        vuln_types = self._identify_vuln_types(content)
        severity = self._detect_severity(content)

        return ExtractedMethodology(
            id=f"meth_{int(time.time())}_{len(self._methodologies)}",
            title=source.title or "Untitled Methodology",
            attack_vector=vuln_types[0] if vuln_types else "unknown",
            steps=steps[:10],
            payloads=self._extract_payloads(content),
            severity=severity,
            source=source.url,
            confidence=0.5 + (0.1 * min(len(steps), 5)),
        )

    def _extract_payloads(self, content: str) -> List[str]:
        payloads = []
        for pattern in PAYLOAD_EXTRACTION_PATTERNS:
            matches = re.findall(pattern, content, re.DOTALL)
            payloads.extend(matches[:5])
        return payloads[:10]

    def _extract_pattern(self, source: ResearchSource, vtype: str,
                          payloads: List[str]) -> Optional[ExploitPattern]:
        return ExploitPattern(
            id=f"pat_{vtype}_{int(time.time())}",
            pattern_type=vtype,
            description=source.title or f"{vtype} pattern",
            test_payloads=payloads[:5],
            source_count=1,
        )

    def _detect_severity(self, content: str) -> str:
        content_lower = content.lower()
        for sev, patterns in SEVERITY_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, content_lower):
                    return sev
        return "medium"

    def generate_skill_from_research(self, methodology_id: str) -> Optional[Dict[str, Any]]:
        """Generate a reusable skill from an extracted methodology."""
        meth = next((m for m in self._methodologies if m.id == methodology_id), None)
        if not meth:
            return None
        return {
            "name": meth.title,
            "category": meth.attack_vector,
            "description": f"Auto-generated from research: {meth.source}",
            "reasoning_heuristics": [f"Step {i+1}: {s}" for i, s in enumerate(meth.steps)],
            "payloads": meth.payloads,
            "severity": meth.severity,
            "confidence": meth.confidence,
            "auto_generated": True,
        }

    def get_patterns_for_vector(self, attack_vector: str) -> List[ExploitPattern]:
        return [p for p in self._patterns.values() if p.pattern_type == attack_vector]

    def get_summary(self) -> Dict[str, Any]:
        return {
            "total_sources": len(self._sources),
            "by_type": dict(self._ingestion_stats),
            "methodologies": len(self._methodologies),
            "patterns": len(self._patterns),
            "total_payloads": sum(
                len(m.payloads) for m in self._methodologies
            ),
        }
