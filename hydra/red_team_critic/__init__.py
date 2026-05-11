"""
╔══════════════════════════════════════════════════════════════╗
║  Red-Team Critic Agent — 5th Debate Agent                    ║
║  Adversarial offensive reasoning, exploit-chain critic,      ║
║  operational tradecraft analysis, stealth evaluation          ║
╚══════════════════════════════════════════════════════════════╝
"""

import logging
import time
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger("hydra.red_team_critic")


@dataclass
class RedTeamCritique:
    """A red-team critique of a finding or plan."""
    id: str = ""
    target: str = ""              # finding_id, plan_id, theory_id
    critique_type: str = ""       # tradecraft, stealth, chain, scope, operational
    severity: str = "medium"      # critical, high, medium, low
    issue: str = ""
    recommendation: str = ""
    confidence: float = 0.5
    operational_risk: float = 0.0
    timestamp: float = field(default_factory=time.time)


# ── Tradecraft Rules ─────────────────────────

TRADECRAFT_RULES = [
    {
        "id": "TRC-001",
        "name": "Excessive Noise",
        "check": lambda ctx: ctx.get("requests_count", 0) > 1000,
        "issue": "Operation generated excessive traffic (>1000 requests)",
        "recommendation": "Reduce scan intensity, use targeted probing",
        "severity": "high",
    },
    {
        "id": "TRC-002",
        "name": "Predictable User-Agent",
        "check": lambda ctx: any(
            tool in ctx.get("user_agent", "").lower()
            for tool in ["sqlmap", "nikto", "nmap", "dirbuster", "gobuster", "python-requests"]
        ),
        "issue": "Tool-identifiable User-Agent detected",
        "recommendation": "Rotate User-Agents with realistic browser fingerprints",
        "severity": "high",
    },
    {
        "id": "TRC-003",
        "name": "Sequential Scanning",
        "check": lambda ctx: ctx.get("sequential_pattern", False),
        "issue": "Sequential scan pattern detected — easily fingerprinted",
        "recommendation": "Randomize target order and vary timing intervals",
        "severity": "medium",
    },
    {
        "id": "TRC-004",
        "name": "No Evidence Validation",
        "check": lambda ctx: not ctx.get("evidence_validated", False),
        "issue": "Finding reported without validation — false positive risk",
        "recommendation": "Validate with independent reproduction and debate system",
        "severity": "critical",
    },
    {
        "id": "TRC-005",
        "name": "Scope Boundary Risk",
        "check": lambda ctx: ctx.get("near_scope_boundary", False),
        "issue": "Operation near scope boundary — risk of out-of-scope action",
        "recommendation": "Verify scope explicitly before proceeding",
        "severity": "critical",
    },
    {
        "id": "TRC-006",
        "name": "Unencrypted Exfiltration",
        "check": lambda ctx: ctx.get("protocol", "").lower() == "http",
        "issue": "Data transmitted over unencrypted HTTP",
        "recommendation": "Use HTTPS for all interactions",
        "severity": "medium",
    },
    {
        "id": "TRC-007",
        "name": "Missing Stealth Wrapper",
        "check": lambda ctx: ctx.get("stealth_mode", "") in ("aggressive", ""),
        "issue": "Operating without stealth controls",
        "recommendation": "Enable stealth mode before active testing",
        "severity": "high",
    },
    {
        "id": "TRC-008",
        "name": "Exploit Without Simulation",
        "check": lambda ctx: not ctx.get("simulated", False),
        "issue": "Exploit attempted without pre-execution simulation",
        "recommendation": "Run simulation engine before any active exploitation",
        "severity": "high",
    },
    {
        "id": "TRC-009",
        "name": "Single-Vector Fixation",
        "check": lambda ctx: ctx.get("vectors_tested", 1) < 2,
        "issue": "Only one attack vector explored — limited reasoning",
        "recommendation": "Generate and evaluate multiple exploit theories",
        "severity": "medium",
    },
    {
        "id": "TRC-010",
        "name": "Deception Not Checked",
        "check": lambda ctx: not ctx.get("deception_checked", False),
        "issue": "Target not checked for deception (honeypots, canaries)",
        "recommendation": "Run deception detection engine before deep testing",
        "severity": "high",
    },
]


class RedTeamCriticAgent:
    """
    5th debate agent — Red-Team Critic.

    Evaluates findings and plans from an offensive tradecraft perspective:
      - Operational security assessment
      - Exploit-chain viability
      - Stealth evaluation
      - Evidence quality from attacker perspective
      - Scope compliance
      - Deception awareness

    Asks questions that the other 4 debate agents don't:
      "Would a real red team do this?"
      "Is this operationally viable?"
      "Does the stealth profile match the threat model?"
      "Are we wasting time on decoys?"
      "Does this chain actually lead to impact?"
    """

    def __init__(self):
        self._critiques: List[RedTeamCritique] = []

    def critique_finding(self, finding: Dict[str, Any],
                          context: Dict[str, Any] = None) -> List[RedTeamCritique]:
        """Critique a security finding from red-team perspective."""
        context = context or {}
        context.update(finding)
        critiques = []

        # Apply tradecraft rules
        for rule in TRADECRAFT_RULES:
            try:
                if rule["check"](context):
                    critique = RedTeamCritique(
                        id=rule["id"],
                        target=finding.get("id", ""),
                        critique_type="tradecraft",
                        severity=rule["severity"],
                        issue=rule["issue"],
                        recommendation=rule["recommendation"],
                        confidence=0.8,
                    )
                    critiques.append(critique)
            except Exception:
                pass

        # Exploit chain viability
        chain_critique = self._evaluate_exploit_chain(finding, context)
        if chain_critique:
            critiques.append(chain_critique)

        # Evidence quality from attacker perspective
        evidence_critique = self._evaluate_evidence_quality(finding)
        if evidence_critique:
            critiques.append(evidence_critique)

        # Operational impact assessment
        impact_critique = self._evaluate_operational_impact(finding)
        if impact_critique:
            critiques.append(impact_critique)

        self._critiques.extend(critiques)
        return critiques

    def critique_plan(self, plan_steps: List[Dict[str, Any]],
                       context: Dict[str, Any] = None) -> List[RedTeamCritique]:
        """Critique an attack plan from red-team perspective."""
        context = context or {}
        critiques = []

        # Check for missing simulation
        if not context.get("simulated"):
            critiques.append(RedTeamCritique(
                critique_type="operational",
                severity="high",
                issue="Plan not validated via simulation engine",
                recommendation="Run environment simulator before execution",
            ))

        # Check for stealth considerations
        aggressive_steps = [s for s in plan_steps if
                            s.get("type", "") in ("fuzz", "brute", "scan")]
        if aggressive_steps and not context.get("stealth_configured"):
            critiques.append(RedTeamCritique(
                critique_type="stealth",
                severity="high",
                issue=f"{len(aggressive_steps)} aggressive steps without stealth config",
                recommendation="Configure stealth engine before aggressive testing",
            ))

        # Check for deception awareness
        if not context.get("deception_checked"):
            critiques.append(RedTeamCritique(
                critique_type="operational",
                severity="medium",
                issue="Targets not checked for deception infrastructure",
                recommendation="Run deception detection before committing resources",
            ))

        self._critiques.extend(critiques)
        return critiques

    def _evaluate_exploit_chain(self, finding: Dict,
                                 context: Dict) -> Optional[RedTeamCritique]:
        """Evaluate if an exploit chain is operationally viable."""
        severity = finding.get("severity", "medium")
        evidence = finding.get("evidence", [])

        if severity in ("critical", "high") and len(evidence) < 2:
            return RedTeamCritique(
                critique_type="chain",
                severity="high",
                issue=f"{severity} finding with insufficient evidence ({len(evidence)} pieces)",
                recommendation="A real red team would need reproduction proof before reporting",
                operational_risk=0.7,
            )
        return None

    def _evaluate_evidence_quality(self, finding: Dict) -> Optional[RedTeamCritique]:
        """Evaluate evidence quality from attacker perspective."""
        evidence = finding.get("evidence", [])
        description = finding.get("description", "")

        # Check for speculative language
        speculative = ["might", "could", "possibly", "potentially", "appears to"]
        if any(word in description.lower() for word in speculative):
            return RedTeamCritique(
                critique_type="tradecraft",
                severity="medium",
                issue="Finding uses speculative language — not evidence-backed",
                recommendation="Replace speculation with observed behavior and proof",
                confidence=0.7,
            )
        return None

    def _evaluate_operational_impact(self, finding: Dict) -> Optional[RedTeamCritique]:
        """Evaluate real-world operational impact."""
        severity = finding.get("severity", "")
        vuln_type = finding.get("type", "").lower()

        # Low-impact findings marked high severity
        low_impact_types = ["open_redirect", "version_disclosure", "missing_header"]
        if severity in ("critical", "high") and any(t in vuln_type for t in low_impact_types):
            return RedTeamCritique(
                critique_type="operational",
                severity="medium",
                issue=f"'{vuln_type}' marked as {severity} — likely over-rated",
                recommendation="Reassess impact: would this achieve objective in a real engagement?",
            )
        return None

    def get_overall_assessment(self) -> Dict[str, Any]:
        """Get overall red-team assessment."""
        if not self._critiques:
            return {"status": "no_critiques", "score": 1.0}

        critical = sum(1 for c in self._critiques if c.severity == "critical")
        high = sum(1 for c in self._critiques if c.severity == "high")
        medium = sum(1 for c in self._critiques if c.severity == "medium")

        score = max(0.0, 1.0 - (critical * 0.3 + high * 0.15 + medium * 0.05))

        return {
            "total_critiques": len(self._critiques),
            "critical": critical,
            "high": high,
            "medium": medium,
            "operational_readiness_score": round(score, 2),
            "recommendation": (
                "BLOCKED — critical issues must be resolved" if critical > 0
                else "CAUTION — address high-priority issues" if high > 0
                else "PROCEED — minor improvements recommended" if medium > 0
                else "CLEAR — no tradecraft issues detected"
            ),
        }

    def get_summary(self) -> Dict[str, Any]:
        return self.get_overall_assessment()
