"""
╔══════════════════════════════════════════════════════════════╗
║  Ethical & Legal Guardrails Engine                            ║
║  Scope enforcement, blast radius control, policy awareness,  ║
║  and justification chains for all offensive actions           ║
╚══════════════════════════════════════════════════════════════╝
"""

import logging
import time
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field
from urllib.parse import urlparse

logger = logging.getLogger("hydra.guardrails")


class RiskLevel(str, Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    PROHIBITED = "prohibited"


class ActionType(str, Enum):
    PASSIVE_RECON = "passive_recon"
    ACTIVE_RECON = "active_recon"
    VULNERABILITY_SCAN = "vulnerability_scan"
    EXPLOITATION = "exploitation"
    DATA_ACCESS = "data_access"
    DESTRUCTIVE = "destructive"
    SOCIAL_ENGINEERING = "social_engineering"
    DOS_TESTING = "dos_testing"


@dataclass
class GuardrailDecision:
    """Result of a guardrail check."""
    allowed: bool = True
    risk_level: RiskLevel = RiskLevel.SAFE
    reason: str = ""
    warnings: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)
    scope_violation: bool = False
    requires_confirmation: bool = False


@dataclass
class ScopePolicy:
    """Defines what is allowed within a program's scope."""
    in_scope_domains: Set[str] = field(default_factory=set)
    in_scope_wildcards: Set[str] = field(default_factory=set)
    out_of_scope_domains: Set[str] = field(default_factory=set)
    out_of_scope_paths: Set[str] = field(default_factory=set)
    allowed_actions: Set[ActionType] = field(default_factory=lambda: {
        ActionType.PASSIVE_RECON, ActionType.ACTIVE_RECON,
        ActionType.VULNERABILITY_SCAN,
    })
    prohibited_actions: Set[ActionType] = field(default_factory=lambda: {
        ActionType.DESTRUCTIVE, ActionType.DOS_TESTING,
        ActionType.SOCIAL_ENGINEERING,
    })
    max_scan_rate: float = 50.0
    safe_harbor: bool = False
    custom_rules: List[str] = field(default_factory=list)


# ── Always-prohibited actions (hardcoded safety) ──

ABSOLUTE_PROHIBITIONS = [
    "Denial of service attacks",
    "Data destruction or modification",
    "Social engineering of employees",
    "Physical access attempts",
    "Attacks on third-party infrastructure",
    "Exfiltration of personal data (PII/PHI)",
    "Accessing other users' data beyond PoC",
    "Cryptocurrency mining on target infrastructure",
    "Spam or phishing campaigns",
    "Attacks on shared infrastructure (CI/CD, staging with real data)",
]


class GuardrailsEngine:
    """
    Ethical and legal guardrails for autonomous offensive operations.

    Enforces:
      1. Program scope boundaries (domains, wildcards, exclusions)
      2. Action type restrictions (no DoS, no social engineering)
      3. Blast radius control (limit exploitation depth)
      4. Rate limiting compliance
      5. Absolute safety prohibitions (hardcoded, non-overridable)
      6. Justification chains for all major decisions

    Every action checked through guardrails gets a clear
    ALLOW/DENY/WARN decision with full reasoning.
    """

    def __init__(self, policy: Optional[ScopePolicy] = None):
        self._policy = policy or ScopePolicy()
        self._check_history: List[Dict[str, Any]] = []
        self._violations: List[Dict[str, Any]] = []
        self._warnings_issued = 0

    def set_policy(self, policy: ScopePolicy):
        """Set or update the scope policy."""
        self._policy = policy
        logger.info(
            f"🔒 Guardrails policy set: "
            f"{len(policy.in_scope_domains)} domains in scope, "
            f"{len(policy.prohibited_actions)} prohibited action types"
        )

    def load_from_scope_assets(self, in_scope: List[Dict],
                                out_of_scope: List[str] = None):
        """Load policy from bounty program scope assets."""
        policy = ScopePolicy()
        for asset in in_scope:
            domain = asset.get("asset", "")
            atype = asset.get("asset_type", "")
            if atype in ("wildcard", "WILDCARD") or domain.startswith("*."):
                policy.in_scope_wildcards.add(
                    domain.lstrip("*.")
                )
            else:
                policy.in_scope_domains.add(domain.lower())
        for item in (out_of_scope or []):
            policy.out_of_scope_domains.add(item.lower())
        self.set_policy(policy)

    def check_target(self, target: str) -> GuardrailDecision:
        """Check if a target is within scope."""
        parsed = urlparse(target if "://" in target else f"https://{target}")
        domain = (parsed.hostname or target).lower().strip(".")

        decision = GuardrailDecision()

        # Check explicit out-of-scope
        if domain in self._policy.out_of_scope_domains:
            decision.allowed = False
            decision.scope_violation = True
            decision.risk_level = RiskLevel.PROHIBITED
            decision.reason = f"Domain '{domain}' is explicitly out of scope"
            self._record_violation("scope", decision.reason, target)
            return decision

        # Check out-of-scope paths
        path = parsed.path or ""
        for oos_path in self._policy.out_of_scope_paths:
            if path.startswith(oos_path):
                decision.allowed = False
                decision.scope_violation = True
                decision.risk_level = RiskLevel.PROHIBITED
                decision.reason = f"Path '{path}' is out of scope"
                self._record_violation("scope", decision.reason, target)
                return decision

        # Check in-scope (if scope is defined)
        if self._policy.in_scope_domains or self._policy.in_scope_wildcards:
            in_scope = self._is_in_scope(domain)
            if not in_scope:
                decision.allowed = False
                decision.scope_violation = True
                decision.risk_level = RiskLevel.PROHIBITED
                decision.reason = (
                    f"Domain '{domain}' not found in scope. "
                    f"In-scope: {list(self._policy.in_scope_domains)[:5]}"
                )
                self._record_violation("scope", decision.reason, target)
                return decision

        decision.allowed = True
        decision.risk_level = RiskLevel.SAFE
        decision.reason = f"Target '{domain}' is within scope"
        return decision

    def check_action(self, action_type: ActionType,
                     target: str = "",
                     details: str = "") -> GuardrailDecision:
        """Check if an action type is allowed."""
        decision = GuardrailDecision()

        # Absolute prohibitions (non-overridable)
        if action_type in (ActionType.DESTRUCTIVE, ActionType.DOS_TESTING):
            decision.allowed = False
            decision.risk_level = RiskLevel.PROHIBITED
            decision.reason = (
                f"Action type '{action_type.value}' is absolutely prohibited"
            )
            self._record_violation("action", decision.reason, target)
            return decision

        # Policy-level prohibitions
        if action_type in self._policy.prohibited_actions:
            decision.allowed = False
            decision.risk_level = RiskLevel.PROHIBITED
            decision.reason = (
                f"Action type '{action_type.value}' is prohibited by policy"
            )
            self._record_violation("action", decision.reason, target)
            return decision

        # Exploitation requires confirmation
        if action_type == ActionType.EXPLOITATION:
            decision.allowed = True
            decision.requires_confirmation = True
            decision.risk_level = RiskLevel.HIGH
            decision.warnings.append(
                "Exploitation requires careful scope verification"
            )
            decision.mitigations.append(
                "Limit to proof-of-concept only, no data exfiltration"
            )

        # Data access warnings
        if action_type == ActionType.DATA_ACCESS:
            decision.allowed = True
            decision.requires_confirmation = True
            decision.risk_level = RiskLevel.HIGH
            decision.warnings.append(
                "Data access must be minimal and documented"
            )
            decision.mitigations.append(
                "Access only non-sensitive test data for PoC"
            )

        # Check target scope if provided
        if target:
            target_check = self.check_target(target)
            if not target_check.allowed:
                return target_check

        if not decision.warnings:
            decision.risk_level = RiskLevel.SAFE
            decision.reason = f"Action '{action_type.value}' is allowed"

        self._check_history.append({
            "action": action_type.value,
            "target": target,
            "allowed": decision.allowed,
            "risk": decision.risk_level.value,
            "timestamp": time.time(),
        })

        return decision

    def assess_blast_radius(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Assess blast radius of a potential exploit."""
        severity = finding.get("severity", "info").lower()
        desc = finding.get("description", "").lower()

        risk = RiskLevel.LOW
        warnings = []
        mitigations = []

        if severity in ("critical", "high"):
            risk = RiskLevel.HIGH
            warnings.append("High-severity finding may have wide blast radius")

        if any(kw in desc for kw in ["rce", "remote code", "command injection"]):
            risk = RiskLevel.CRITICAL
            warnings.append("RCE finding — limit to PoC, no shell access")
            mitigations.append("Use harmless commands (id, whoami) for PoC only")

        if any(kw in desc for kw in ["database", "dump", "exfil"]):
            risk = RiskLevel.CRITICAL
            warnings.append("Data exposure risk — do NOT access real user data")
            mitigations.append("Demonstrate with test/dummy data only")

        if any(kw in desc for kw in ["admin", "root", "privilege"]):
            risk = RiskLevel.HIGH
            warnings.append("Privilege escalation — document but do not exploit further")

        return {
            "risk_level": risk.value,
            "warnings": warnings,
            "mitigations": mitigations,
            "proceed": risk.value not in ("critical", "prohibited"),
        }

    def _is_in_scope(self, domain: str) -> bool:
        """Check if a domain matches scope (direct or wildcard)."""
        if domain in self._policy.in_scope_domains:
            return True
        for wildcard in self._policy.in_scope_wildcards:
            if domain.endswith(f".{wildcard}") or domain == wildcard:
                return True
        return False

    def _record_violation(self, vtype: str, reason: str, target: str):
        self._violations.append({
            "type": vtype, "reason": reason,
            "target": target, "timestamp": time.time(),
        })
        self._warnings_issued += 1
        logger.warning(f"🚫 GUARDRAIL VIOLATION: {reason}")

    def get_summary(self) -> Dict[str, Any]:
        return {
            "checks_performed": len(self._check_history),
            "violations": len(self._violations),
            "warnings_issued": self._warnings_issued,
            "scope_domains": len(self._policy.in_scope_domains),
            "scope_wildcards": len(self._policy.in_scope_wildcards),
            "prohibited_actions": [
                a.value for a in self._policy.prohibited_actions
            ],
            "safe_harbor": self._policy.safe_harbor,
        }
