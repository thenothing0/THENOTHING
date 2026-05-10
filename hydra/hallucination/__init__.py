"""
╔══════════════════════════════════════════════════════════════╗
║  AI Hallucination Defense Layer — Evidence-First Reasoning   ║
║  Detects unsupported claims, verifies evidence, scores      ║
║  confidence, prevents hallucinated findings in reports       ║
╚══════════════════════════════════════════════════════════════╝

No unsupported AI-generated claim may appear in reports.
"""

import json
import logging
import re
import time
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger("hydra.hallucination")


@dataclass
class ClaimVerification:
    """Verification result for a single claim."""
    claim: str
    verified: bool
    confidence: float
    evidence_sources: List[str] = field(default_factory=list)
    contradictions: List[str] = field(default_factory=list)
    hallucination_score: float = 0.0  # 0 = definitely real, 1 = definitely hallucinated
    verification_method: str = ""
    notes: str = ""


@dataclass
class HallucinationReport:
    """Full hallucination analysis report."""
    total_claims: int = 0
    verified_claims: int = 0
    unverified_claims: int = 0
    suspected_hallucinations: int = 0
    overall_hallucination_score: float = 0.0
    claims: List[ClaimVerification] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


# ──────────────────────────────────────────────
#  Hallucination Indicator Patterns
# ──────────────────────────────────────────────

HALLUCINATION_INDICATORS = [
    # Vague/unsubstantiated language
    re.compile(r'\b(?:likely|probably|possibly|might|could be|appears to be|seems)\b', re.I),
    # Fabricated CVE numbers (invalid format)
    re.compile(r'CVE-\d{4}-\d{1,3}(?!\d)'),  # Too short to be real
    # Overly specific claims without evidence
    re.compile(r'(?:confirmed|verified|proven|demonstrated)\s+(?:that|the)', re.I),
    # Generic security buzzwords without specifics
    re.compile(r'\b(?:critical vulnerability|severe flaw|major security issue)\b(?!\s*:)', re.I),
]

EVIDENCE_INDICATORS = [
    # HTTP response codes
    re.compile(r'HTTP/[\d.]+ \d{3}|status[:\s]+\d{3}', re.I),
    # Actual URLs
    re.compile(r'https?://\S+'),
    # Tool output references
    re.compile(r'\b(?:nuclei|nmap|httpx|subfinder|ffuf|dirsearch)\b', re.I),
    # Specific technical details
    re.compile(r'\b(?:port \d+|header:|cookie:|parameter:|endpoint:)\b', re.I),
    # CVE references (valid format)
    re.compile(r'CVE-\d{4}-\d{4,}'),
    # IP addresses
    re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),
    # File paths
    re.compile(r'(?:/[a-zA-Z0-9._-]+){2,}'),
]

CONTRADICTION_PATTERNS = [
    # Contradictory severity claims
    ("critical", "low risk"),
    ("high severity", "informational"),
    ("confirmed vulnerability", "no evidence"),
    ("verified", "unable to reproduce"),
    ("exploitable", "no exploit available"),
    ("unauthenticated", "requires authentication"),
]


class HallucinationDefense:
    """
    AI Hallucination Defense Layer.

    Requirements:
      - Unsupported claim detection
      - Evidence-first reasoning
      - Contradiction detection
      - Multi-agent verification
      - Confidence aggregation
      - Hallucination scoring

    No unsupported AI-generated claim may appear in reports.
    """

    def __init__(self):
        self._verified_findings: Dict[str, ClaimVerification] = {}
        self._evidence_store: Dict[str, List[Dict]] = {}

    def register_evidence(self, finding_id: str, evidence: Dict[str, Any]):
        """Register evidence for a finding."""
        if finding_id not in self._evidence_store:
            self._evidence_store[finding_id] = []
        self._evidence_store[finding_id].append({
            **evidence,
            "registered_at": time.time(),
        })

    def verify_finding(self, finding: Dict[str, Any],
                        tool_outputs: Optional[List[Dict]] = None,
                        agent_assessments: Optional[List[Dict]] = None) -> ClaimVerification:
        """
        Verify a finding against evidence.

        Uses multiple verification strategies:
          1. Evidence presence check
          2. Hallucination indicator scanning
          3. Contradiction detection
          4. Multi-agent consensus (if available)
          5. Confidence aggregation
        """
        finding_id = finding.get("template_id", finding.get("id", str(hash(str(finding)))[:12]))
        name = finding.get("name", "")
        description = finding.get("description", "")
        full_text = f"{name} {description}"

        verification = ClaimVerification(
            claim=name or str(finding)[:200],
            verified=False,
            confidence=0.0,
        )

        # Step 1: Check for actual evidence
        evidence_score = self._check_evidence(finding, tool_outputs)
        verification.evidence_sources = evidence_score["sources"]

        # Step 2: Scan for hallucination indicators
        hallucination_indicators = self._detect_hallucination_indicators(full_text)
        
        # Step 3: Scan for evidence indicators
        evidence_indicators = self._detect_evidence_indicators(full_text)

        # Step 4: Contradiction detection
        contradictions = self._detect_contradictions(finding)
        verification.contradictions = contradictions

        # Step 5: Multi-agent consensus
        consensus_score = 0.0
        if agent_assessments:
            consensus_score = self._compute_consensus(agent_assessments)

        # Step 6: Aggregate hallucination score
        hallucination_score = self._compute_hallucination_score(
            evidence_count=len(verification.evidence_sources),
            hallucination_indicators=len(hallucination_indicators),
            evidence_indicators=len(evidence_indicators),
            contradictions=len(contradictions),
            consensus=consensus_score,
            has_tool_output=bool(tool_outputs),
            severity=finding.get("severity", "info"),
        )

        verification.hallucination_score = hallucination_score
        verification.confidence = 1.0 - hallucination_score
        verification.verified = hallucination_score < 0.5

        if hallucination_score >= 0.7:
            verification.verification_method = "BLOCKED — suspected hallucination"
            verification.notes = (
                f"Hallucination indicators: {len(hallucination_indicators)}, "
                f"Evidence sources: {len(verification.evidence_sources)}, "
                f"Contradictions: {len(contradictions)}"
            )
        elif hallucination_score >= 0.5:
            verification.verification_method = "WARNING — low evidence confidence"
        else:
            verification.verification_method = "PASSED — evidence-backed"

        self._verified_findings[finding_id] = verification
        return verification

    def _check_evidence(self, finding: Dict, tool_outputs: Optional[List[Dict]]) -> Dict:
        """Check if finding has supporting evidence."""
        sources = []

        # Check finding itself for evidence
        if finding.get("matched_at"):
            sources.append("matched_at")
        if finding.get("evidence"):
            sources.append("tool_evidence")
        if finding.get("extracted-results"):
            sources.append("extracted_results")
        if finding.get("template_id"):
            sources.append("nuclei_template")
        if finding.get("curl-command"):
            sources.append("curl_command")

        # Check tool outputs
        finding_id = finding.get("template_id", "")
        if finding_id in self._evidence_store:
            for ev in self._evidence_store[finding_id]:
                sources.append(f"registered:{ev.get('type', 'unknown')}")

        if tool_outputs:
            for output in tool_outputs:
                if output.get("success") and finding.get("name", "").lower() in output.get("output", "").lower():
                    sources.append(f"tool:{output.get('tool_used', 'unknown')}")

        return {"sources": sources, "count": len(sources)}

    def _detect_hallucination_indicators(self, text: str) -> List[str]:
        """Detect language patterns that suggest hallucination."""
        found = []
        for pattern in HALLUCINATION_INDICATORS:
            matches = pattern.findall(text)
            for m in matches:
                found.append(m if isinstance(m, str) else str(m))
        return found

    def _detect_evidence_indicators(self, text: str) -> List[str]:
        """Detect language patterns that suggest real evidence."""
        found = []
        for pattern in EVIDENCE_INDICATORS:
            matches = pattern.findall(text)
            for m in matches:
                found.append(m if isinstance(m, str) else str(m))
        return found

    def _detect_contradictions(self, finding: Dict) -> List[str]:
        """Detect contradictions within a finding."""
        contradictions = []
        full_text = json.dumps(finding, default=str).lower()

        for term_a, term_b in CONTRADICTION_PATTERNS:
            if term_a.lower() in full_text and term_b.lower() in full_text:
                contradictions.append(f"Contradiction: '{term_a}' vs '{term_b}'")

        return contradictions

    def _compute_consensus(self, assessments: List[Dict]) -> float:
        """Compute multi-agent consensus score."""
        if not assessments:
            return 0.0

        verdicts = [a.get("is_valid", False) for a in assessments]
        if not verdicts:
            return 0.0

        agreement = sum(verdicts) / len(verdicts)
        return agreement

    def _compute_hallucination_score(
        self,
        evidence_count: int,
        hallucination_indicators: int,
        evidence_indicators: int,
        contradictions: int,
        consensus: float,
        has_tool_output: bool,
        severity: str,
    ) -> float:
        """
        Compute overall hallucination probability score.

        0.0 = definitely real
        1.0 = definitely hallucinated
        """
        score = 0.5  # Start neutral

        # Evidence reduces hallucination probability
        score -= evidence_count * 0.08
        score -= evidence_indicators * 0.03

        # Tool output is strong evidence
        if has_tool_output:
            score -= 0.15

        # Hallucination indicators increase probability
        score += hallucination_indicators * 0.06

        # Contradictions are strong hallucination signal
        score += contradictions * 0.15

        # Multi-agent consensus
        if consensus > 0:
            score -= consensus * 0.20

        # Higher severity claims need more evidence
        severity_penalty = {
            "critical": 0.10, "high": 0.08,
            "medium": 0.04, "low": 0.02, "info": 0.0,
        }
        score += severity_penalty.get(severity.lower(), 0.05)

        return max(0.0, min(1.0, score))

    def batch_verify(self, findings: List[Dict],
                      tool_outputs: Optional[List[Dict]] = None) -> HallucinationReport:
        """Verify a batch of findings and generate a hallucination report."""
        report = HallucinationReport()
        report.total_claims = len(findings)

        for finding in findings:
            verification = self.verify_finding(finding, tool_outputs)
            report.claims.append(verification)

            if verification.verified:
                report.verified_claims += 1
            else:
                report.unverified_claims += 1
                if verification.hallucination_score >= 0.7:
                    report.suspected_hallucinations += 1

        # Overall score
        if report.claims:
            report.overall_hallucination_score = round(
                sum(c.hallucination_score for c in report.claims) / len(report.claims), 4
            )

        # Recommendations
        if report.suspected_hallucinations > 0:
            report.recommendations.append(
                f"⚠️ {report.suspected_hallucinations} findings flagged as potential hallucinations. "
                f"Review evidence before including in reports."
            )
        if report.unverified_claims > report.verified_claims:
            report.recommendations.append(
                "⚠️ More unverified claims than verified. Consider re-running scans with actual tools."
            )
        if report.overall_hallucination_score > 0.4:
            report.recommendations.append(
                "🚨 High overall hallucination score. Evidence quality is below threshold."
            )

        return report

    def filter_verified_findings(self, findings: List[Dict],
                                  min_confidence: float = 0.5) -> List[Dict]:
        """Return only findings that pass hallucination defense."""
        verified = []
        for finding in findings:
            verification = self.verify_finding(finding)
            if verification.confidence >= min_confidence and verification.verified:
                finding["hallucination_score"] = verification.hallucination_score
                finding["evidence_confidence"] = verification.confidence
                verified.append(finding)
            else:
                logger.info(
                    f"🛡️ Finding filtered by hallucination defense: "
                    f"{finding.get('name', 'unknown')} "
                    f"(score={verification.hallucination_score:.2f})"
                )
        return verified

    def get_summary(self) -> Dict[str, Any]:
        total = len(self._verified_findings)
        verified = sum(1 for v in self._verified_findings.values() if v.verified)
        return {
            "total_verified": total,
            "passed": verified,
            "failed": total - verified,
            "avg_hallucination_score": round(
                sum(v.hallucination_score for v in self._verified_findings.values())
                / max(total, 1), 4
            ),
            "evidence_store_size": sum(len(v) for v in self._evidence_store.values()),
        }
