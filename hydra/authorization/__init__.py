"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  Bug-Bounty Authorization Gate                                                 ║
║  DENY-BY-DEFAULT enforcement: the platform may take an active / exploitation   ║
║  action ONLY against a target that is provably in-scope for a registered bug   ║
║  bounty program. Anything else is denied.                                      ║
╚══════════════════════════════════════════════════════════════════════════════╝

This module is the safety keystone that lets Hydra move from advisory modelling toward actual
vulnerability *validation/exploitation* WITHOUT losing the platform's #1 non-negotiable
("Written authorization only"). A live bug bounty program's published scope IS written
authorization — so the gate's rule is simple and strict:

    authorize(target, action) → ALLOW  ⇔  target ∈ in-scope(some registered bounty program)
                                          ∧ target ∉ out-of-scope(any registered program)
                                          ∧ action is not an absolute prohibition
                                          (exploitation is permitted PoC-only)

Unlike the existing `ScopePolicyEngine` / `GuardrailsEngine` (which ALLOW when no scope is loaded),
this gate is **deny-by-default**: with no covering program, every active action is denied. It reuses
the guardrails' hard prohibitions (DoS / destructive / data-exfil / social-engineering are NEVER
allowed) and the scope module's program model. Pure/deterministic decision logic (the registry is the
only state); every decision is audited.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from hydra.guardrails import ABSOLUTE_PROHIBITIONS, ActionType, GuardrailsEngine, RiskLevel

# Recognised bug bounty platforms. "Any site that has a bug bounty program" is expressed by
# registering that program's scope (custom platform allowed) — but a platform tag is recorded so the
# authorization provenance is explicit.
KNOWN_PLATFORMS = frozenset({
    "hackerone", "bugcrowd", "intigriti", "yeswehack", "hackenproof",
    "immunefi", "synack", "openbugbounty", "self_hosted", "custom",
})

_DATA = Path(__file__).resolve().parents[2] / "data"

# Active actions that require bug-bounty authorization (passive recon is informational only).
_ACTIVE = {
    ActionType.ACTIVE_RECON, ActionType.VULNERABILITY_SCAN,
    ActionType.EXPLOITATION, ActionType.DATA_ACCESS,
}


class AuthorizationError(PermissionError):
    """Raised by `require()` when an action is not authorized by any bug bounty program."""


@dataclass
class AuthorizationDecision:
    authorized: bool
    target: str
    host: str
    action: str
    program: Optional[str] = None
    platform: Optional[str] = None
    matched_asset: Optional[str] = None
    reason: str = ""
    risk_level: str = RiskLevel.SAFE.value
    poc_only: bool = False
    prohibited: bool = False
    scope_violation: bool = False
    mitigations: List[str] = field(default_factory=list)
    audit_id: str = ""
    timestamp: float = 0.0

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class BountyProgram:
    """A registered bug bounty program = published authorization for testing its in-scope assets."""
    program: str
    platform: str
    in_scope: List[str] = field(default_factory=list)
    out_of_scope: List[str] = field(default_factory=list)
    url: str = ""
    registered_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict:
        return asdict(self)


def _host_of(target: str) -> str:
    """Deterministically extract the lowercased hostname from a target (url, host, or host:port)."""
    t = (target or "").strip()
    if not t:
        return ""
    parsed = urlparse(t if "://" in t else f"https://{t}")
    host = (parsed.hostname or "").lower().strip(".")
    return host


def _asset_matches(host: str, asset: str) -> Tuple[bool, str]:
    """Conservative, deny-by-default-friendly matching.

    * `*.example.com`  → matches example.com and any subdomain (wildcard).
    * `example.com`    → matches EXACTLY that host (a bare apex does NOT silently cover subdomains;
                          programs must wildcard to authorize subdomains — the safe interpretation).
    Returns (matched, normalized_asset)."""
    if not host or not asset:
        return False, ""
    a = asset.strip().lower()
    a = _host_of(a) if "://" in a else a.split("/")[0].strip(".")
    if not a:
        return False, ""
    if a.startswith("*."):
        suffix = a[2:]
        return (host == suffix or host.endswith("." + suffix)), asset
    return (host == a), asset


class BugBountyAuthorizationGate:
    """Deny-by-default authorization for active/exploitation actions against bug-bounty targets."""

    def __init__(self, registry_path: Optional[str] = None, load: bool = True):
        self._programs: Dict[str, BountyProgram] = {}
        self._audit: List[Dict] = []
        self._guardrails = GuardrailsEngine()
        self._path = Path(registry_path or os.environ.get("HYDRA_AUTHORIZED_PROGRAMS")
                          or (_DATA / "authorized_programs.json"))
        if load:
            self._load()

    # ── registry (the operator's declared, authorized programs) ──────────────────
    def register_program(self, program: str, platform: str, in_scope: List[str],
                         out_of_scope: Optional[List[str]] = None, url: str = "",
                         persist: bool = True) -> BountyProgram:
        platform = (platform or "custom").lower()
        if platform not in KNOWN_PLATFORMS:
            raise ValueError(f"unknown platform '{platform}'; use one of {sorted(KNOWN_PLATFORMS)}")
        if not in_scope:
            raise ValueError("a bug bounty program must declare at least one in-scope asset")
        bp = BountyProgram(program=program, platform=platform,
                           in_scope=[a.strip() for a in in_scope if a.strip()],
                           out_of_scope=[a.strip() for a in (out_of_scope or []) if a.strip()],
                           url=url)
        self._programs[program] = bp
        if persist:
            self._save()
        return bp

    def register_scope(self, scope, persist: bool = True) -> BountyProgram:
        """Register from a `hydra.scope.ProgramScope` (e.g. fetched live from HackerOne/Bugcrowd)."""
        ins = [a.get("asset", "") for a in getattr(scope, "in_scope", []) if a.get("asset")]
        oos = [a.get("asset", "") for a in getattr(scope, "out_of_scope", []) if a.get("asset")]
        return self.register_program(getattr(scope, "program_name", "") or "program",
                                     getattr(scope, "platform", "custom"), ins, oos,
                                     getattr(scope, "program_url", ""), persist=persist)

    def programs(self) -> List[Dict]:
        return [p.to_dict() for p in sorted(self._programs.values(), key=lambda p: p.program)]

    # ── the gate ──────────────────────────────────────────────────────────────────
    def _covering(self, host: str) -> Tuple[Optional[BountyProgram], str]:
        """First program whose in-scope covers `host` (deterministic order); ('',) if none."""
        for name in sorted(self._programs):
            for asset in self._programs[name].in_scope:
                matched, norm = _asset_matches(host, asset)
                if matched:
                    return self._programs[name], norm
        return None, ""

    def _excluded(self, host: str) -> Tuple[Optional[BountyProgram], str]:
        for name in sorted(self._programs):
            for asset in self._programs[name].out_of_scope:
                matched, norm = _asset_matches(host, asset)
                if matched:
                    return self._programs[name], norm
        return None, ""

    def authorize(self, target: str, action: str = "exploitation") -> AuthorizationDecision:
        ts = time.time()
        host = _host_of(target)
        try:
            atype = ActionType(action)
        except ValueError:
            atype = ActionType.EXPLOITATION
        d = AuthorizationDecision(authorized=False, target=target, host=host,
                                  action=atype.value, timestamp=ts)
        d.audit_id = hashlib.sha256(
            f"{host}|{atype.value}|{ts}".encode()).hexdigest()[:16]

        # 1) Invalid target → deny.
        if not host:
            d.reason = "no resolvable host in target"
            d.risk_level = RiskLevel.PROHIBITED.value
            return self._record(d)

        # 2) Absolute prohibitions are NEVER allowed, even in-scope.
        action_check = self._guardrails.check_action(atype)
        if not action_check.allowed:
            d.prohibited = True
            d.risk_level = RiskLevel.PROHIBITED.value
            d.reason = action_check.reason or f"action '{atype.value}' is absolutely prohibited"
            return self._record(d)

        # 3) Explicit out-of-scope on ANY registered program → deny.
        excl, masset = self._excluded(host)
        if excl is not None:
            d.scope_violation = True
            d.program, d.platform, d.matched_asset = excl.program, excl.platform, masset
            d.risk_level = RiskLevel.PROHIBITED.value
            d.reason = f"'{host}' is explicitly OUT OF SCOPE for program '{excl.program}'"
            return self._record(d)

        # 4) DENY-BY-DEFAULT: a covering bug bounty program is REQUIRED.
        prog, masset = self._covering(host)
        if prog is None:
            d.scope_violation = True
            d.risk_level = RiskLevel.PROHIBITED.value
            d.reason = (f"DENIED (deny-by-default): no registered bug bounty program authorizes "
                        f"'{host}'. The platform only acts on bug-bounty-covered targets.")
            return self._record(d)

        # 5) Authorized. Exploitation/data-access are PoC-only.
        d.authorized = True
        d.program, d.platform, d.matched_asset = prog.program, prog.platform, masset
        if atype in (ActionType.EXPLOITATION, ActionType.DATA_ACCESS):
            d.poc_only = True
            d.risk_level = RiskLevel.HIGH.value
            d.mitigations = ["proof-of-concept only — no data exfiltration beyond a minimal PoC",
                             "no destructive actions; no DoS; stop at demonstrable impact",
                             *action_check.mitigations]
            d.reason = (f"AUTHORIZED (PoC-only) by '{prog.program}' [{prog.platform}] — "
                        f"matched in-scope asset '{masset}'")
        else:
            d.risk_level = RiskLevel.SAFE.value
            d.reason = (f"AUTHORIZED by '{prog.program}' [{prog.platform}] — "
                        f"matched in-scope asset '{masset}'")
        return self._record(d)

    def require(self, target: str, action: str = "exploitation") -> AuthorizationDecision:
        """Hard gate: authorize or raise. Call this immediately before any active action."""
        d = self.authorize(target, action)
        if not d.authorized:
            raise AuthorizationError(d.reason)
        return d

    # ── audit ──────────────────────────────────────────────────────────────────────
    def _record(self, d: AuthorizationDecision) -> AuthorizationDecision:
        self._audit.append({"audit_id": d.audit_id, "target": d.target, "host": d.host,
                            "action": d.action, "authorized": d.authorized,
                            "program": d.program, "reason": d.reason, "timestamp": d.timestamp})
        return d

    def audit_log(self) -> List[Dict]:
        return list(self._audit)

    @property
    def absolute_prohibitions(self) -> List[str]:
        return list(ABSOLUTE_PROHIBITIONS)

    # ── persistence (operator-owned config; JSON; rebuildable) ───────────────────
    def _load(self) -> None:
        try:
            if self._path.exists():
                raw = json.loads(self._path.read_text(encoding="utf-8"))
                for p in raw.get("programs", []):
                    bp = BountyProgram(**{k: p[k] for k in p if k in BountyProgram.__annotations__})
                    self._programs[bp.program] = bp
        except Exception:
            self._programs = {}

    def _save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(json.dumps(
                {"programs": [p.to_dict() for p in self._programs.values()]}, indent=2),
                encoding="utf-8")
        except Exception:
            pass


__all__ = [
    "BugBountyAuthorizationGate",
    "AuthorizationDecision",
    "AuthorizationError",
    "BountyProgram",
    "KNOWN_PLATFORMS",
]
