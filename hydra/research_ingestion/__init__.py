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
    "xss": [re.compile(r"cross.?site.?script"), re.compile(r"\bxss\b"), re.compile(r"reflected.?xss"), re.compile(r"stored.?xss"), re.compile(r"dom.?xss")],
    "sqli": [re.compile(r"sql.?inject"), re.compile(r"\bsqli\b"), re.compile(r"union.?select"), re.compile(r"blind.?sql")],
    "ssrf": [re.compile(r"server.?side.?request"), re.compile(r"\bssrf\b"), re.compile(r"internal.?request")],
    "idor": [re.compile(r"insecure.?direct.?object"), re.compile(r"\bidor\b"), re.compile(r"broken.?access")],
    "rce": [re.compile(r"remote.?code.?exec"), re.compile(r"\brce\b"), re.compile(r"command.?inject")],
    "auth_bypass": [re.compile(r"auth(entication)?.?bypass"), re.compile(r"jwt.?bypass"), re.compile(r"session.?fixation")],
    "ssti": [re.compile(r"server.?side.?template"), re.compile(r"\bssti\b"), re.compile(r"template.?inject")],
    "csrf": [re.compile(r"cross.?site.?request.?forg"), re.compile(r"\bcsrf\b")],
    "xxe": [re.compile(r"xml.?external.?entity"), re.compile(r"\bxxe\b")],
    "deserialization": [re.compile(r"deserializ"), re.compile(r"unserialize"), re.compile(r"pickle"), re.compile(r"java\.io")],
    "path_traversal": [re.compile(r"path.?travers"), re.compile(r"directory.?travers"), re.compile(r"local.?file.?incl"), re.compile(r"\blfi\b")],
    "open_redirect": [re.compile(r"open.?redirect"), re.compile(r"url.?redirect")],
    "race_condition": [re.compile(r"race.?condition"), re.compile(r"toctou"), re.compile(r"concurrency")],
}

PAYLOAD_EXTRACTION_PATTERNS = [
    re.compile(r'(?:payload|vector|poc|input)\s*[:=]\s*["\'](.+?)["\']'),
    re.compile(r'(?:curl|wget|http)\s+.*?(?:[\'"](https?://\S+)["\'])'),
    re.compile(r'```(?:http|bash|sh|curl)?\s*\n(.+?)\n```', re.DOTALL),
]

SEVERITY_PATTERNS = {
    "critical": [re.compile(r"\bcritical\b"), re.compile(r"cvss.{0,10}9\.\d"), re.compile(r"\brce\b"), re.compile(r"remote.?code")],
    "high": [re.compile(r"\bhigh\b"), re.compile(r"cvss.{0,10}[7-8]\.\d"), re.compile(r"account.?takeover"), re.compile(r"\bato\b")],
    "medium": [re.compile(r"\bmedium\b"), re.compile(r"cvss.{0,10}[4-6]\.\d")],
    "low": [re.compile(r"\blow\b"), re.compile(r"cvss.{0,10}[1-3]\.\d"), re.compile(r"informational")],
}


_STEP_PATTERNS = [
    re.compile(r'(?:^|\n)\s*\d+[\.\)]\s*(.+)', re.IGNORECASE | re.MULTILINE),
    re.compile(r'(?:^|\n)\s*[-*]\s*(.+)', re.IGNORECASE | re.MULTILINE),
    re.compile(r'(?:step|phase)\s*\d+\s*[:\.]\s*(.+)', re.IGNORECASE | re.MULTILINE),
]


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
                if pattern.search(content_lower):
                    found.append(vtype)
                    break
        return found

    def _extract_methodology(self, source: ResearchSource) -> Optional[ExtractedMethodology]:
        content = source.content
        if not content or len(content) < 100:
            return None

        # Extract steps (numbered lists, bullet points)
        steps = []
        for pattern in _STEP_PATTERNS:
            matches = pattern.findall(content)
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
            matches = pattern.findall(content)
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
                if pattern.search(content_lower):
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
