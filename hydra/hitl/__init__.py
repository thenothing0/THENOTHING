"""
Human-In-The-Loop Security System (architecture spec Part 8).

Risk-tiered approval policy over tool calls. Classifies a (tool, args) into a
risk level, then maps (risk × operator-mode) to the allowed decisions:

    LOW       → auto-allow (logged)
    MEDIUM    → allow-once | allow-session | deny
    HIGH      → allow-once | allow-workflow | deny      (allow-session disabled)
    CRITICAL  → allow-once | deny | EMERGENCY-STOP      (no caching)
    PROHIBITED→ HARD DENY (never offered, even under operator/YOLO)

Operator/YOLO mode auto-approves LOW–CRITICAL *friction*, but PROHIBITED and the
scope gate stay hard (consistent with the platform invariant). An emergency stop
trips a global flag that hard-denies everything until reset.

Advisory/deterministic; the actual modal is the harness's — this decides policy.
"""

from .policy import (
    RISK_OF_TOOL,
    ApprovalPolicy,
    Decision,
    RiskLevel,
    classify_risk,
)

__all__ = [
    "ApprovalPolicy",
    "RiskLevel",
    "Decision",
    "classify_risk",
    "RISK_OF_TOOL",
]
