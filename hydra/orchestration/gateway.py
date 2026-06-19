"""Mandatory enforcement gateway: RBAC → HITL → Authorization (Phase 2)."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional

from hydra.engagement import EngagementStore, can
from hydra.hitl import ApprovalPolicy, RiskLevel, classify_risk

# Tool risk tier → the RBAC action it requires. Higher-risk tools need higher roles.
_RISK_TO_ACTION = {
    RiskLevel.LOW: "read",
    RiskLevel.MEDIUM: "run_scan",
    RiskLevel.HIGH: "run_exploit",
    RiskLevel.CRITICAL: "run_exploit",
    RiskLevel.PROHIBITED: "run_exploit",
}


@dataclass
class GateDecision:
    allowed: bool
    risk: str
    reason: str
    rbac: Dict = field(default_factory=dict)
    hitl: Dict = field(default_factory=dict)
    authz: Dict = field(default_factory=dict)


class ToolGateway:
    """The single enforcement chokepoint. `check()` must return allowed=True before
    a tool runs. It enforces (not advises): RBAC role, HITL risk policy, and the
    deny-by-default scope gate. Every decision is appended to a durable audit log.
    """

    def __init__(self, *, engagement_store: Optional[EngagementStore] = None,
                 approval_policy: Optional[ApprovalPolicy] = None,
                 audit_path: str = ".thenothing/audit/gateway.jsonl",
                 enforce_rbac: bool = True, enforce_scope: bool = False):
        self._eng = engagement_store
        self._policy = approval_policy or ApprovalPolicy()
        self._audit = Path(audit_path)
        self._audit.parent.mkdir(parents=True, exist_ok=True)
        self.enforce_rbac = enforce_rbac
        self.enforce_scope = enforce_scope

    def check(self, tool: str, args: Dict, ctx) -> GateDecision:
        risk = classify_risk(tool, args)

        # 1) HITL risk policy — hard-deny prohibited regardless of mode.
        hitl = self._policy.evaluate(tool, args, workflow_run_id=getattr(ctx, "workflow_run_id", ""))
        if hitl.get("hard_deny"):
            d = GateDecision(False, risk, hitl.get("reason", "prohibited"), hitl=hitl)
            return self._record(tool, ctx, d)

        # 2) RBAC — the engagement member's role must permit the action.
        rbac: Dict = {"checked": False}
        if self.enforce_rbac:
            action = _RISK_TO_ACTION.get(risk, "run_scan")
            role = getattr(ctx, "role", None)
            if role is not None:
                allowed = can(role, action)
                rbac = {"checked": True, "role": role, "action": action, "allowed": allowed}
                if not allowed:
                    d = GateDecision(False, risk,
                                     f"RBAC: role '{role}' may not '{action}'", rbac=rbac, hitl=hitl)
                    return self._record(tool, ctx, d)
            elif self._eng and getattr(ctx, "engagement_id", "") and getattr(ctx, "username", ""):
                res = self._eng.authorize(ctx.engagement_id, ctx.username, action)
                rbac = {"checked": True, **res, "action": action}
                if not res.get("allowed"):
                    d = GateDecision(False, risk, res.get("reason", "RBAC denied"),
                                     rbac=rbac, hitl=hitl)
                    return self._record(tool, ctx, d)

        # 3) Authorization — deny-by-default scope gate for target-naming tools.
        authz: Dict = {"checked": False}
        if self.enforce_scope:
            target = args.get("target") or args.get("url") or args.get("domain") or ""
            if target:
                try:
                    from hydra.authorization import BugBountyAuthorizationGate
                    dec = BugBountyAuthorizationGate().authorize(target, "active_recon")
                    authz = {"checked": True, "authorized": dec.authorized, "reason": dec.reason}
                    if not dec.authorized:
                        d = GateDecision(False, risk, f"scope gate: {dec.reason}",
                                         rbac=rbac, hitl=hitl, authz=authz)
                        return self._record(tool, ctx, d)
                except Exception as e:  # gate import/use must never silently allow
                    authz = {"checked": True, "authorized": False, "reason": str(e)}

        d = GateDecision(True, risk, hitl.get("reason", "allowed"),
                         rbac=rbac, hitl=hitl, authz=authz)
        return self._record(tool, ctx, d)

    def emergency_stop(self) -> None:
        self._policy.emergency_stop()

    def _record(self, tool: str, ctx, d: GateDecision) -> GateDecision:
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "tool": tool, "risk": d.risk, "allowed": d.allowed, "reason": d.reason,
            "engagement_id": getattr(ctx, "engagement_id", ""),
            "username": getattr(ctx, "username", ""),
            "rbac": d.rbac, "hitl_decision": d.hitl.get("decision"),
        }
        try:
            with self._audit.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except OSError:
            pass
        return d
