"""
╔══════════════════════════════════════════════════════════════╗
║  Heuristic Reasoning Engine — Adaptive Scan Intelligence    ║
║  Prioritizes likely vulnerabilities, adapts scans, reduces  ║
║  noise, optimizes attack paths, minimizes detection          ║
╚══════════════════════════════════════════════════════════════╝
"""

import logging
import math
import time
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger("hydra.heuristics")


@dataclass
class HeuristicSignal:
    """A signal that influences heuristic decisions."""
    name: str
    source: str  # fingerprint, header, scan, osint, history
    weight: float = 1.0
    confidence: float = 0.5
    data: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


@dataclass
class HeuristicDecision:
    """A heuristic-driven decision."""
    action: str  # prioritize, skip, expand, deep_scan, reduce_noise
    target: str
    reason: str
    confidence: float = 0.5
    priority: int = 2  # 0=critical, 1=high, 2=normal, 3=low
    signals_used: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VulnerabilityLikelihood:
    """Estimated likelihood of a vulnerability class on a target."""
    vuln_class: str
    likelihood: float  # 0.0 - 1.0
    confidence: float  # 0.0 - 1.0
    supporting_signals: List[str] = field(default_factory=list)
    recommended_tests: List[str] = field(default_factory=list)


# ──────────────────────────────────────────────
#  Vulnerability Prior Probabilities
# ──────────────────────────────────────────────

# Base probability of each vuln class (from real-world data)
VULN_PRIORS = {
    "xss": 0.15,
    "sqli": 0.08,
    "ssrf": 0.06,
    "idor": 0.12,
    "auth_bypass": 0.07,
    "information_disclosure": 0.20,
    "misconfiguration": 0.18,
    "open_redirect": 0.09,
    "csrf": 0.10,
    "file_upload": 0.04,
    "path_traversal": 0.05,
    "rce": 0.03,
    "jwt_weakness": 0.06,
    "deserialization": 0.03,
    "subdomain_takeover": 0.04,
    "cors_misconfiguration": 0.08,
    "rate_limiting": 0.10,
    "mass_assignment": 0.05,
    "graphql_injection": 0.04,
    "api_key_exposure": 0.07,
}

# Technology → vulnerability boosters
TECH_VULN_BOOSTERS = {
    "WordPress": {"xss": 1.5, "sqli": 1.3, "file_upload": 2.0, "auth_bypass": 1.4, "information_disclosure": 1.5},
    "Next.js": {"ssrf": 1.8, "auth_bypass": 1.6, "information_disclosure": 1.5, "open_redirect": 1.3},
    "Laravel": {"rce": 1.5, "deserialization": 2.0, "sqli": 1.3, "misconfiguration": 1.4},
    "Django": {"sqli": 1.2, "csrf": 1.1, "misconfiguration": 1.3},
    "Express": {"ssrf": 1.4, "idor": 1.3, "rate_limiting": 1.5},
    "GraphQL": {"idor": 1.8, "information_disclosure": 1.6, "graphql_injection": 3.0, "rate_limiting": 1.5},
    "Firebase": {"misconfiguration": 2.0, "auth_bypass": 1.5, "information_disclosure": 1.8},
    "AWS": {"ssrf": 2.0, "misconfiguration": 1.8, "api_key_exposure": 1.5},
    "React": {"xss": 0.7, "open_redirect": 1.2},  # React reduces XSS probability
    "PHP": {"sqli": 1.5, "xss": 1.3, "file_upload": 1.4, "rce": 1.3},
    "Java": {"deserialization": 1.8, "sqli": 1.2, "path_traversal": 1.3},
    "Ruby on Rails": {"mass_assignment": 2.0, "csrf": 1.2, "idor": 1.3},
    "ASP.NET": {"deserialization": 1.5, "path_traversal": 1.3},
}


class HeuristicReasoningEngine:
    """
    Adaptive heuristic reasoning for security assessment optimization.

    Capabilities:
      - Prioritize likely vulnerabilities based on technology stack
      - Adapt scans dynamically based on findings
      - Optimize attack paths using confidence scoring
      - Minimize unnecessary noise (reduce false positives)
      - Reduce detectable scanning footprint
      - Learn from historical results
    """

    def __init__(self, learning_engine=None):
        self._signals: List[HeuristicSignal] = []
        self._decisions: List[HeuristicDecision] = []
        self._technologies: List[str] = []
        self._findings: List[Dict[str, Any]] = []
        self._learning = learning_engine

    def add_signal(self, signal: HeuristicSignal):
        """Add a heuristic signal from any source."""
        self._signals.append(signal)
        logger.debug(f"📊 Signal added: {signal.name} ({signal.source}, conf={signal.confidence})")

    def add_technology(self, tech_name: str):
        """Register a detected technology."""
        if tech_name not in self._technologies:
            self._technologies.append(tech_name)

    def add_finding(self, finding: Dict[str, Any]):
        """Register a scan finding for adaptive reasoning."""
        self._findings.append(finding)

    def estimate_vulnerability_likelihoods(self) -> List[VulnerabilityLikelihood]:
        """
        Estimate vulnerability likelihoods using Bayesian-style reasoning.

        Combines:
          - Base vulnerability priors
          - Technology-specific boosters
          - Signal-based adjustments
          - Historical accuracy data
        """
        likelihoods = []

        for vuln_class, base_prob in VULN_PRIORS.items():
            adjusted = base_prob
            signals_used = []

            # Apply technology boosters
            for tech in self._technologies:
                boosters = TECH_VULN_BOOSTERS.get(tech, {})
                if vuln_class in boosters:
                    adjusted *= boosters[vuln_class]
                    signals_used.append(f"tech:{tech}")

            # Apply signal-based adjustments
            for signal in self._signals:
                if vuln_class in signal.data.get("vuln_boost", {}):
                    boost = signal.data["vuln_boost"][vuln_class]
                    adjusted *= boost * signal.confidence
                    signals_used.append(f"signal:{signal.name}")

            # Apply historical accuracy if available
            if self._learning:
                try:
                    # Use synchronous check (learning engine is sync)
                    hist_weight = self._learning.get_routing_weight(f"vuln:{vuln_class}")
                    if hist_weight != 0.5:  # Non-default weight
                        adjusted *= (0.5 + hist_weight)
                        signals_used.append("history")
                except Exception:
                    pass

            # Normalize to [0, 1]
            adjusted = min(1.0, max(0.0, adjusted))

            # Confidence based on number of supporting signals
            confidence = min(0.95, 0.3 + len(signals_used) * 0.15)

            # Generate recommended tests
            tests = self._get_recommended_tests(vuln_class)

            likelihoods.append(VulnerabilityLikelihood(
                vuln_class=vuln_class,
                likelihood=round(adjusted, 4),
                confidence=round(confidence, 4),
                supporting_signals=signals_used,
                recommended_tests=tests,
            ))

        # Sort by likelihood (highest first)
        likelihoods.sort(key=lambda v: v.likelihood, reverse=True)
        return likelihoods

    def prioritize_scans(self, available_tools: List[str]) -> List[HeuristicDecision]:
        """
        Generate prioritized scan decisions.

        Returns ordered list of actions based on heuristic analysis.
        """
        decisions = []
        likelihoods = self.estimate_vulnerability_likelihoods()

        for vl in likelihoods:
            if vl.likelihood < 0.05:
                continue  # Skip very unlikely vulns

            if vl.likelihood >= 0.15:
                action = "prioritize"
                priority = 0 if vl.likelihood >= 0.25 else 1
            elif vl.likelihood >= 0.08:
                action = "scan"
                priority = 2
            else:
                action = "scan_low"
                priority = 3

            decisions.append(HeuristicDecision(
                action=action,
                target=vl.vuln_class,
                reason=f"Likelihood={vl.likelihood:.2f}, signals={','.join(vl.supporting_signals[:3])}",
                confidence=vl.confidence,
                priority=priority,
                signals_used=vl.supporting_signals,
                metadata={
                    "recommended_tests": vl.recommended_tests,
                    "vuln_class": vl.vuln_class,
                },
            ))

        # Add adaptive decisions based on current findings
        adaptive = self._generate_adaptive_decisions()
        decisions.extend(adaptive)

        # Sort by priority
        decisions.sort(key=lambda d: (d.priority, -d.confidence))
        self._decisions = decisions
        return decisions

    def _generate_adaptive_decisions(self) -> List[HeuristicDecision]:
        """Generate decisions based on current findings."""
        decisions = []

        # If we found critical/high vulns, expand investigation
        critical_findings = [
            f for f in self._findings
            if f.get("severity", "").lower() in ("critical", "high")
        ]
        if critical_findings:
            decisions.append(HeuristicDecision(
                action="deep_scan",
                target="validation",
                reason=f"Found {len(critical_findings)} critical/high findings — validate immediately",
                confidence=0.9,
                priority=0,
                signals_used=["findings"],
            ))

        # If many info/low findings, possible noise — reduce scan depth
        low_findings = [
            f for f in self._findings
            if f.get("severity", "").lower() in ("info", "low")
        ]
        if len(low_findings) > 20 and len(critical_findings) == 0:
            decisions.append(HeuristicDecision(
                action="reduce_noise",
                target="scan_depth",
                reason=f"High noise ratio ({len(low_findings)} info/low, 0 critical) — reduce scan depth",
                confidence=0.7,
                priority=2,
            ))

        # If SSRF-like findings, expand to cloud metadata
        ssrf_findings = [f for f in self._findings if "ssrf" in str(f).lower()]
        if ssrf_findings:
            decisions.append(HeuristicDecision(
                action="expand",
                target="cloud_metadata",
                reason="SSRF detected — expand to cloud metadata endpoint testing",
                confidence=0.8,
                priority=0,
            ))

        return decisions

    def get_scan_profile(self) -> Dict[str, Any]:
        """
        Generate optimized scan profile based on heuristic analysis.

        Returns configuration for scan depth, speed, and focus areas.
        """
        likelihoods = self.estimate_vulnerability_likelihoods()
        top_vulns = [v for v in likelihoods if v.likelihood >= 0.10]

        # Determine scan aggressiveness
        high_value_target = len(top_vulns) >= 5
        has_waf = any(s.name == "waf_detected" for s in self._signals)

        profile = {
            "scan_depth": "deep" if high_value_target else "standard",
            "rate_limit": 10 if has_waf else 50,
            "stealth_mode": has_waf,
            "priority_vuln_classes": [v.vuln_class for v in top_vulns[:10]],
            "nuclei_severity": "medium,high,critical",
            "expand_recon": high_value_target,
            "technologies_detected": self._technologies,
            "signal_count": len(self._signals),
            "finding_count": len(self._findings),
        }

        if has_waf:
            profile["delay_between_requests"] = 0.5
            profile["user_agent_rotation"] = True
            profile["header_randomization"] = True

        return profile

    def _get_recommended_tests(self, vuln_class: str) -> List[str]:
        """Get recommended tests for a vulnerability class."""
        test_map = {
            "xss": ["nuclei -tags xss", "param fuzzing", "DOM analysis"],
            "sqli": ["nuclei -tags sqli", "sqlmap", "error-based detection"],
            "ssrf": ["nuclei -tags ssrf", "URL parameter testing", "metadata endpoint"],
            "idor": ["API endpoint enumeration", "ID manipulation", "access control testing"],
            "auth_bypass": ["auth flow testing", "token manipulation", "session testing"],
            "information_disclosure": ["nuclei -tags exposure", "header analysis", "error page analysis"],
            "misconfiguration": ["nuclei -tags misconfig", "security header check", "default credential check"],
            "rce": ["nuclei -tags rce", "command injection testing", "deserialization testing"],
            "jwt_weakness": ["JWT analysis", "algorithm confusion", "key brute force"],
            "cors_misconfiguration": ["CORS header testing", "origin reflection check"],
            "subdomain_takeover": ["CNAME check", "dangling DNS", "cloud service check"],
        }
        return test_map.get(vuln_class, [f"nuclei -tags {vuln_class}"])

    def get_confidence_score(self, finding: Dict[str, Any]) -> float:
        """
        Calculate confidence score for a finding using heuristic analysis.

        Combines:
          - Base severity score
          - Technology context
          - Signal correlation
          - Historical accuracy
        """
        score = 0.4
        severity = finding.get("severity", "info").lower()
        score += {"critical": 0.3, "high": 0.2, "medium": 0.1, "low": 0.0, "info": -0.1}.get(severity, 0)

        # Boost if finding type matches high-likelihood vuln
        finding_type = finding.get("type", "").lower()
        likelihoods = {v.vuln_class: v.likelihood for v in self.estimate_vulnerability_likelihoods()}
        for vuln_class, likelihood in likelihoods.items():
            if vuln_class in finding_type:
                score += likelihood * 0.3
                break

        # Evidence boost
        if finding.get("evidence") or finding.get("matched_at"):
            score += 0.1

        return max(0.0, min(1.0, score))

    def get_summary(self) -> Dict[str, Any]:
        return {
            "signals": len(self._signals),
            "technologies": self._technologies,
            "findings_analyzed": len(self._findings),
            "decisions_made": len(self._decisions),
            "top_likelihoods": [
                {"vuln": v.vuln_class, "likelihood": v.likelihood}
                for v in self.estimate_vulnerability_likelihoods()[:5]
            ],
        }
