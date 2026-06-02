"""
╔══════════════════════════════════════════════════════════════╗
║  Multi-Agent Debate System — Adversarial Reasoning Engine   ║
║  Hypothesis / Skeptic / Validation / Risk agents debate     ║
║  findings before acceptance. Self-critique + hallucination  ║
║  defense via evidence-backed adversarial reasoning          ║
╚══════════════════════════════════════════════════════════════╝
"""

import logging
import time
from enum import Enum
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger("hydra.debate")


class DebateRole(str, Enum):
    HYPOTHESIS = "hypothesis"      # Proposes vulnerabilities, generates exploit theories
    SKEPTIC = "skeptic"           # Attacks assumptions, searches for contradictions
    VALIDATOR = "validator"       # Verifies evidence, confirms reproducibility
    RISK = "risk"                 # Estimates impact, scores blast radius


class Verdict(str, Enum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    NEEDS_MORE_EVIDENCE = "needs_more_evidence"
    DEFERRED = "deferred"


@dataclass
class DebateArgument:
    """A single argument in a debate round."""
    role: DebateRole
    position: str                  # support, challenge, neutral
    claim: str
    evidence: List[str] = field(default_factory=list)
    confidence: float = 0.5
    reasoning: str = ""
    weaknesses_identified: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)


@dataclass
class DebateFinding:
    """A finding submitted for debate."""
    id: str
    title: str
    description: str
    severity: str = "medium"
    evidence: List[str] = field(default_factory=list)
    source_agent: str = ""
    initial_confidence: float = 0.5
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DebateOutcome:
    """Final outcome of a multi-agent debate."""
    finding_id: str
    verdict: Verdict
    final_confidence: float
    rounds: int
    arguments: List[DebateArgument] = field(default_factory=list)
    accepted_evidence: List[str] = field(default_factory=list)
    rejected_reasons: List[str] = field(default_factory=list)
    risk_assessment: Dict[str, Any] = field(default_factory=dict)
    reasoning_trace: str = ""
    duration: float = 0.0


# ──────────────────────────────────────────────
#  Skeptic Analysis Rules
# ──────────────────────────────────────────────

HALLUCINATION_INDICATORS = [
    "likely", "possibly", "might be", "could be", "probably",
    "appears to be", "seems like", "it is assumed", "theoretically",
    "based on common patterns", "generally speaking", "in most cases",
]

CONTRADICTION_PATTERNS = [
    (["critical", "severe"], ["low risk", "informational", "minor"]),
    (["confirmed", "verified"], ["unverified", "unconfirmed", "theoretical"]),
    (["exploitable", "weaponized"], ["not exploitable", "no impact"]),
    (["authenticated"], ["unauthenticated", "no auth"]),
]

EVIDENCE_REQUIREMENTS = {
    "critical": ["http_response", "reproduction_steps", "screenshot_or_artifact"],
    "high": ["http_response", "reproduction_steps"],
    "medium": ["http_response"],
    "low": ["description"],
    "info": ["description"],
}


class HypothesisAgent:
    """Proposes vulnerabilities and generates exploit theories."""

    def propose(self, finding: DebateFinding) -> DebateArgument:
        """Generate a hypothesis argument supporting the finding."""
        evidence_strength = self._evaluate_evidence(finding.evidence)
        exploit_plausibility = self._evaluate_plausibility(finding)

        confidence = (evidence_strength * 0.6 + exploit_plausibility * 0.4)

        return DebateArgument(
            role=DebateRole.HYPOTHESIS,
            position="support",
            claim=f"Finding '{finding.title}' is a valid {finding.severity} vulnerability",
            evidence=finding.evidence,
            confidence=confidence,
            reasoning=(
                f"Evidence strength: {evidence_strength:.2f}. "
                f"Exploit plausibility: {exploit_plausibility:.2f}. "
                f"Source: {finding.source_agent}."
            ),
        )

    def _evaluate_evidence(self, evidence: List[str]) -> float:
        if not evidence:
            return 0.1
        score = min(len(evidence) * 0.2, 0.8)
        # Bonus for strong evidence types
        for e in evidence:
            if any(kw in e.lower() for kw in ["http/1", "status:", "200 ok", "response"]):
                score += 0.1
            if any(kw in e.lower() for kw in ["screenshot", "proof", "artifact"]):
                score += 0.1
        return min(score, 1.0)

    def _evaluate_plausibility(self, finding: DebateFinding) -> float:
        base = 0.5
        if finding.severity in ("critical", "high"):
            base -= 0.1  # Higher bar for severe findings
        if finding.source_agent in ("validation_agent", "exploit_agent"):
            base += 0.2  # Trust validated sources more
        return min(base, 1.0)


class SkepticAgent:
    """Attacks assumptions and searches for contradictions."""

    def challenge(self, finding: DebateFinding,
                  hypothesis: DebateArgument) -> DebateArgument:
        """Challenge a finding with skeptical analysis."""
        weaknesses = []
        confidence_penalty = 0.0

        # Check for hallucination indicators
        desc_lower = finding.description.lower()
        for indicator in HALLUCINATION_INDICATORS:
            if indicator in desc_lower:
                weaknesses.append(f"Hallucination indicator: '{indicator}' suggests uncertainty")
                confidence_penalty += 0.1

        # Check for contradictions
        for positive, negative in CONTRADICTION_PATTERNS:
            has_positive = any(p in desc_lower for p in positive)
            has_negative = any(n in desc_lower for n in negative)
            if has_positive and has_negative:
                weaknesses.append(f"Contradiction: claims both {positive[0]} and {negative[0]}")
                confidence_penalty += 0.2

        # Evidence sufficiency check
        required = EVIDENCE_REQUIREMENTS.get(finding.severity, ["description"])
        for req in required:
            if not any(req.lower() in e.lower() for e in finding.evidence):
                weaknesses.append(f"Missing required evidence: {req}")
                confidence_penalty += 0.15

        # Source credibility
        if not finding.source_agent:
            weaknesses.append("Unknown source agent — cannot assess credibility")
            confidence_penalty += 0.1

        challenged_confidence = max(0.1, hypothesis.confidence - confidence_penalty)

        return DebateArgument(
            role=DebateRole.SKEPTIC,
            position="challenge",
            claim=(f"Finding has {len(weaknesses)} weakness(es) reducing confidence "
                   f"from {hypothesis.confidence:.2f} to {challenged_confidence:.2f}"),
            evidence=finding.evidence,
            confidence=1.0 - challenged_confidence,  # Skeptic's confidence in rejection
            reasoning=f"Identified {len(weaknesses)} issues",
            weaknesses_identified=weaknesses,
        )


class ValidationAgent:
    """Verifies evidence and confirms reproducibility."""

    def validate(self, finding: DebateFinding) -> DebateArgument:
        """Validate evidence quality."""
        checks_passed = 0
        total_checks = 0
        issues = []

        # 1. Evidence presence
        total_checks += 1
        if finding.evidence:
            checks_passed += 1
        else:
            issues.append("No evidence provided")

        # 2. Evidence specificity
        total_checks += 1
        specific_evidence = any(
            any(kw in e.lower() for kw in ["http/", "status", "response", "curl", "request"])
            for e in finding.evidence
        )
        if specific_evidence:
            checks_passed += 1
        else:
            issues.append("No HTTP-level evidence (request/response)")

        # 3. Reproduction feasibility
        total_checks += 1
        has_steps = any("step" in e.lower() or "reproduce" in e.lower() for e in finding.evidence)
        if has_steps or finding.metadata.get("reproduction_steps"):
            checks_passed += 1
        else:
            issues.append("No reproduction steps provided")

        # 4. Severity justification
        total_checks += 1
        if finding.severity in ("low", "info") or len(finding.evidence) >= 2:
            checks_passed += 1
        else:
            issues.append(f"Severity '{finding.severity}' requires stronger evidence")

        validation_score = checks_passed / total_checks if total_checks else 0

        return DebateArgument(
            role=DebateRole.VALIDATOR,
            position="support" if validation_score > 0.6 else "challenge",
            claim=f"Validation score: {validation_score:.0%} ({checks_passed}/{total_checks} checks)",
            evidence=finding.evidence,
            confidence=validation_score,
            reasoning=f"Passed {checks_passed}/{total_checks} checks. Issues: {'; '.join(issues) if issues else 'None'}",
            weaknesses_identified=issues,
        )


class RiskAgent:
    """Estimates impact and evaluates exploitability."""

    def assess(self, finding: DebateFinding,
               debate_arguments: List[DebateArgument]) -> DebateArgument:
        """Assess risk and blast radius."""
        risk_factors = {
            "severity": self._severity_score(finding.severity),
            "evidence_quality": self._evidence_quality(finding, debate_arguments),
            "exploitability": self._exploitability(finding),
            "blast_radius": self._blast_radius(finding),
        }

        risk_score = sum(risk_factors.values()) / len(risk_factors)

        return DebateArgument(
            role=DebateRole.RISK,
            position="support" if risk_score > 0.5 else "neutral",
            claim=f"Risk score: {risk_score:.2f} — {self._risk_label(risk_score)}",
            confidence=risk_score,
            reasoning=(
                f"Severity={risk_factors['severity']:.2f}, "
                f"Evidence={risk_factors['evidence_quality']:.2f}, "
                f"Exploitability={risk_factors['exploitability']:.2f}, "
                f"Blast radius={risk_factors['blast_radius']:.2f}"
            ),
        )

    def _severity_score(self, severity: str) -> float:
        return {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.3, "info": 0.1}.get(severity, 0.3)

    def _evidence_quality(self, finding: DebateFinding,
                          arguments: List[DebateArgument]) -> float:
        validator_args = [a for a in arguments if a.role == DebateRole.VALIDATOR]
        if validator_args:
            return validator_args[-1].confidence
        return 0.3 if finding.evidence else 0.1

    def _exploitability(self, finding: DebateFinding) -> float:
        desc = finding.description.lower()
        if any(kw in desc for kw in ["rce", "remote code execution", "shell"]):
            return 0.95
        if any(kw in desc for kw in ["sqli", "injection", "ssrf"]):
            return 0.8
        if any(kw in desc for kw in ["xss", "csrf", "redirect"]):
            return 0.6
        return 0.4

    def _blast_radius(self, finding: DebateFinding) -> float:
        desc = finding.description.lower()
        if any(kw in desc for kw in ["all users", "admin", "database", "credential"]):
            return 0.9
        if any(kw in desc for kw in ["account", "session", "token"]):
            return 0.6
        return 0.3

    def _risk_label(self, score: float) -> str:
        if score >= 0.8:
            return "CRITICAL — immediate action required"
        if score >= 0.6:
            return "HIGH — prioritize for review"
        if score >= 0.4:
            return "MEDIUM — standard review"
        return "LOW — monitor"


class DebateEngine:
    """
    Multi-Agent Debate System.

    Implements adversarial reasoning between 4 agents:
      1. Hypothesis Agent — proposes vulnerabilities
      2. Skeptic Agent — attacks assumptions, detects hallucinations
      3. Validation Agent — verifies evidence quality
      4. Risk Agent — estimates impact and blast radius

    Process:
      - Hypothesis proposes
      - Skeptic challenges
      - Validator verifies
      - Risk assesses
      - Engine computes final verdict via weighted scoring

    Self-critique: findings must survive adversarial scrutiny
    before being accepted into reports.
    """

    ACCEPTANCE_THRESHOLD = 0.55
    STRONG_ACCEPTANCE = 0.75

    def __init__(self):
        self._hypothesis = HypothesisAgent()
        self._skeptic = SkepticAgent()
        self._validator = ValidationAgent()
        self._risk = RiskAgent()
        self._history: List[DebateOutcome] = []

    def debate(self, finding: DebateFinding, max_rounds: int = 1) -> DebateOutcome:
        """Run a full debate on a finding."""
        start = time.time()
        arguments: List[DebateArgument] = []

        for round_num in range(max_rounds):
            # Round: each agent contributes
            hyp = self._hypothesis.propose(finding)
            arguments.append(hyp)

            skep = self._skeptic.challenge(finding, hyp)
            arguments.append(skep)

            val = self._validator.validate(finding)
            arguments.append(val)

            risk = self._risk.assess(finding, arguments)
            arguments.append(risk)

        # Compute final verdict
        outcome = self._compute_verdict(finding, arguments, time.time() - start)
        self._history.append(outcome)

        level = "INFO" if outcome.verdict == Verdict.ACCEPTED else "WARNING"
        logger.log(
            logging.INFO if outcome.verdict == Verdict.ACCEPTED else logging.WARNING,
            f"Debate [{finding.id}] {outcome.verdict.value} "
            f"(confidence={outcome.final_confidence:.2f}, rounds={outcome.rounds})"
        )
        return outcome

    def _compute_verdict(self, finding: DebateFinding,
                         arguments: List[DebateArgument],
                         duration: float) -> DebateOutcome:
        """Compute weighted verdict from all arguments."""
        weights = {
            DebateRole.HYPOTHESIS: 0.20,
            DebateRole.SKEPTIC: 0.25,
            DebateRole.VALIDATOR: 0.35,
            DebateRole.RISK: 0.20,
        }

        weighted_confidence = 0.0
        for arg in arguments:
            w = weights.get(arg.role, 0.2)
            if arg.position == "support":
                weighted_confidence += arg.confidence * w
            elif arg.position == "challenge":
                weighted_confidence -= arg.confidence * w * 0.5
            else:
                weighted_confidence += arg.confidence * w * 0.3

        final_confidence = max(0.0, min(1.0, weighted_confidence))

        # Determine verdict
        all_weaknesses = []
        for arg in arguments:
            all_weaknesses.extend(arg.weaknesses_identified)

        if final_confidence >= self.STRONG_ACCEPTANCE:
            verdict = Verdict.ACCEPTED
        elif final_confidence >= self.ACCEPTANCE_THRESHOLD:
            if len(all_weaknesses) <= 1:
                verdict = Verdict.ACCEPTED
            else:
                verdict = Verdict.NEEDS_MORE_EVIDENCE
        else:
            if all_weaknesses:
                verdict = Verdict.REJECTED
            else:
                verdict = Verdict.NEEDS_MORE_EVIDENCE

        # Build reasoning trace
        trace_parts = []
        for arg in arguments:
            trace_parts.append(f"[{arg.role.value}] {arg.position}: {arg.claim}")
            if arg.weaknesses_identified:
                trace_parts.append(f"  Weaknesses: {', '.join(arg.weaknesses_identified)}")
        trace_parts.append(f"\nFinal: {verdict.value} (confidence={final_confidence:.2f})")

        # Risk assessment from Risk agent
        risk_args = [a for a in arguments if a.role == DebateRole.RISK]
        risk_data = {"reasoning": risk_args[-1].reasoning} if risk_args else {}

        return DebateOutcome(
            finding_id=finding.id,
            verdict=verdict,
            final_confidence=round(final_confidence, 3),
            rounds=len(arguments) // 4,
            arguments=arguments,
            accepted_evidence=[e for e in finding.evidence if e],
            rejected_reasons=all_weaknesses,
            risk_assessment=risk_data,
            reasoning_trace="\n".join(trace_parts),
            duration=round(duration, 3),
        )

    def get_statistics(self) -> Dict[str, Any]:
        if not self._history:
            return {"total_debates": 0}
        verdicts = {}
        for o in self._history:
            verdicts[o.verdict.value] = verdicts.get(o.verdict.value, 0) + 1
        avg_conf = sum(o.final_confidence for o in self._history) / len(self._history)
        return {
            "total_debates": len(self._history),
            "verdicts": verdicts,
            "avg_confidence": round(avg_conf, 3),
            "acceptance_rate": round(
                verdicts.get("accepted", 0) / len(self._history), 3
            ),
        }
