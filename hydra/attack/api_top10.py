"""
OWASP API Security Top 10 testers (audit improvement #3 — uses the gated executor).

Modern bounties live in APIs. The attack section already had the primitives — dual `SessionContext`
identities, the gated `HttpExecutor`, `AccessControlAnalyzer` — so this module composes them into the
four highest-value API classes:

  * BOLA  (API1, object-level authz)   — generalizes IDOR: does identity B reach identity A's object,
    or does a FOREIGN object id return owned data? (reuses `AccessControlAnalyzer`).
  * BFLA  (API5, function-level authz) — does a LOW-privilege identity reach a privileged FUNCTION,
    including method-based ones (POST/PUT/DELETE/PATCH on admin endpoints)?
  * Mass-assignment (API6)             — does the server bind extra PRIVILEGED fields (role/is_admin/…)
    sent in a write body?
  * Excessive-data-exposure (API3)     — does an API response leak SENSITIVE fields beyond what the
    client needs (password_hash / token / ssn / internal_*)?

Network only via the injected executor (default = the gated, rate-limited `HttpExecutor`); every method
re-checks the bug-bounty authorization gate first (deny-by-default). PoC-only: mass-assignment uses
BENIGN flag values and excessive-data-exposure only READS + LABELS leaked keys (never stores the
values). Findings are `confirmed`/`suspected` with redactable evidence; deterministic given the executor.
"""

from __future__ import annotations

import json
import re
from typing import Dict, List, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from hydra.attack.detection import AccessControlAnalyzer

# Privileged fields an attacker tries to smuggle into a write (benign values; detection only).
DEFAULT_PRIVILEGED_FIELDS = {
    "role": "admin", "is_admin": True, "isAdmin": True, "admin": True,
    "verified": True, "is_verified": True, "account_type": "admin",
    "privilege": "admin", "permissions": "admin", "is_staff": True,
}
# Sensitive response keys that usually should not be returned to a client.
DEFAULT_SENSITIVE_KEYS = [
    "password", "passwd", "password_hash", "pwd_hash", "hash", "salt",
    "ssn", "social_security", "credit_card", "card_number", "cvv",
    "token", "access_token", "refresh_token", "api_key", "apikey", "secret",
    "private_key", "session", "session_id", "auth", "otp", "mfa_secret",
    "internal", "is_admin", "role",
]
# Default privileged functions (method, path) for BFLA force-browse.
DEFAULT_FUNCTIONS = [
    ("GET", "/api/admin"), ("GET", "/api/v1/admin/users"), ("GET", "/api/users"),
    ("POST", "/api/admin/users"), ("DELETE", "/api/users/1"), ("PUT", "/api/users/1/role"),
    ("PATCH", "/api/admin/settings"), ("POST", "/api/v1/admin/export"),
]


def _set_id_param(url: str, param: str, value: str) -> str:
    p = urlparse(url if "://" in url else f"https://{url}")
    q = dict(parse_qsl(p.query, keep_blank_values=True))
    q[param] = value
    return urlunparse(p._replace(query=urlencode(q)))


def _flatten(obj, prefix: str = "") -> List[str]:
    """Yield dotted key paths of a JSON object (so nested sensitive fields are found too)."""
    out: List[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            out.append(key)
            out.extend(_flatten(v, key))
    elif isinstance(obj, list):
        for v in obj[:50]:                       # bounded — APIs can return large arrays
            out.extend(_flatten(v, prefix))
    return out


class APIAttackTester:
    def __init__(self, executor, gate=None, access: Optional[AccessControlAnalyzer] = None):
        if gate is None:
            from hydra.authorization import BugBountyAuthorizationGate
            gate = BugBountyAuthorizationGate()
        self.gate = gate
        self.executor = executor                 # gated HttpExecutor (or DryRunExecutor)
        self.access = access or AccessControlAnalyzer()

    def _deny(self, url: str):
        d = self.gate.authorize(url, "exploitation")
        if not d.authorized:
            return {"target": url, "authorized": False, "reason": d.reason, "advisory": True}
        return None

    # ── API1: BOLA (object-level authorization) ─────────────────────────────────────
    def bola(self, url: str, session_a, session_b, owner_markers: Optional[List[str]] = None,
             id_param: str = "", ids: Optional[List[str]] = None) -> Dict:
        """Fetch identity A's object as A and as B and diff; optionally enumerate foreign object ids as
        B. Confirmed when B receives A's object (or a foreign id returns owned data)."""
        if (deny := self._deny(url)):
            return deny
        u = url if "://" in url else f"https://{url}"
        owner = self.executor(session_a.apply({"method": "GET", "url": u, "headers": {}}))
        other = self.executor(session_b.apply({"method": "GET", "url": u, "headers": {}}))
        verdict, reason, signals = self.access.decide(owner, other, owner_markers)
        rows = [{"url": u, "mode": "cross-identity", "verdict": verdict, "reason": reason,
                 "signals": signals}]
        if id_param and ids:                      # enumerate foreign ids as identity B
            for oid in ids[:20]:
                tu = _set_id_param(u, id_param, str(oid))
                r = self.executor(session_b.apply({"method": "GET", "url": tu, "headers": {}}))
                v, why, sig = self.access.decide(owner, r, owner_markers)
                rows.append({"url": tu, "mode": f"enum {id_param}={oid}", "verdict": v,
                             "reason": why, "signals": sig})
        confirmed = [r for r in rows if r["verdict"] == "confirmed"]
        return {"vuln_class": "bola", "target": u, "authorized": True, "poc_only": True,
                "identity_a": session_a.name, "identity_b": session_b.name,
                "confirmed": bool(confirmed), "results": rows, "confirmed_findings": confirmed,
                "advisory": True}

    # ── API5: BFLA (function-level authorization) ───────────────────────────────────
    def bfla(self, base_url: str, low_priv_session, functions: Optional[List] = None,
             admin_session=None) -> Dict:
        """Call privileged FUNCTIONS (method + path) as a low-priv identity; flag any reachable.
        Optionally diff against admin to separate 'unguarded privileged' from 'public anyway'."""
        if (deny := self._deny(base_url)):
            return deny
        funcs = functions or DEFAULT_FUNCTIONS
        base = base_url if base_url.endswith("/") else base_url + "/"
        rows: List[Dict] = []
        for method, path in funcs:
            url = base + str(path).lstrip("/")
            low = self.executor(low_priv_session.apply(
                {"method": method, "url": url, "headers": {}}))
            if not low.get("executed"):
                continue
            low_ok = (low.get("status") or 0) // 100 == 2
            row = {"method": method, "path": path, "low_priv_status": low.get("status"),
                   "reachable_as_low_priv": low_ok}
            if admin_session is not None:
                adm = self.executor(admin_session.apply(
                    {"method": method, "url": url, "headers": {}}))
                adm_ok = (adm.get("status") or 0) // 100 == 2
                row["admin_status"] = adm.get("status")
                row["bfla"] = bool(low_ok and adm_ok)     # both reach it → low-priv shouldn't
            else:
                row["bfla"] = low_ok
            rows.append(row)
        hits = [r for r in rows if r.get("bfla")]
        return {"vuln_class": "bfla", "target": base_url, "authorized": True, "poc_only": True,
                "tested": len(rows), "results": rows, "confirmed": bool(hits),
                "confirmed_findings": hits,
                "verdict": "candidate" if hits else "suspected",
                "note": "low-priv reached a privileged function — confirm the function is restricted",
                "advisory": True}

    # ── API6: Mass assignment ───────────────────────────────────────────────────────
    def mass_assignment(self, url: str, session, base_body: Optional[Dict] = None,
                        privileged_fields: Optional[Dict] = None, method: str = "PATCH") -> Dict:
        """Send a write with extra PRIVILEGED fields; confirmed when the response reflects an elevated
        field (server bound it). Benign flag values only — never destructive."""
        if (deny := self._deny(url)):
            return deny
        u = url if "://" in url else f"https://{url}"
        priv = privileged_fields or DEFAULT_PRIVILEGED_FIELDS
        body = dict(base_body or {})
        body.update(priv)
        req = {"method": method.upper(), "url": u,
               "headers": {"Content-Type": "application/json"},
               "body": json.dumps(body), "payload": json.dumps(priv)}
        resp = self.executor(session.apply(req))
        snippet = (resp.get("body_snippet") or "")
        reflected = [k for k, v in priv.items()
                     if re.search(rf'"{re.escape(k)}"\s*:\s*{re.escape(json.dumps(v))}', snippet)]
        accepted = (resp.get("status") or 0) // 100 == 2
        verdict = "confirmed" if reflected else ("suspected" if accepted else "refuted")
        return {"vuln_class": "mass_assignment", "target": u, "authorized": True, "poc_only": True,
                "method": method.upper(), "privileged_fields_sent": list(priv.keys()),
                "reflected_privileged_fields": reflected, "status": resp.get("status"),
                "confirmed": bool(reflected), "verdict": verdict,
                "note": "field echoed back at elevated value = server bound a privileged attribute",
                "advisory": True}

    # ── API3: Excessive data exposure ───────────────────────────────────────────────
    def excessive_data_exposure(self, url: str, session=None,
                               sensitive_keys: Optional[List[str]] = None) -> Dict:
        """Fetch a resource and flag SENSITIVE keys present in the JSON response (read + label only —
        the leaked VALUES are never stored)."""
        if (deny := self._deny(url)):
            return deny
        u = url if "://" in url else f"https://{url}"
        req = {"method": "GET", "url": u, "headers": {}}
        if session is not None:
            req = session.apply(req)
        resp = self.executor(req)
        keys = [k.lower() for k in (sensitive_keys or DEFAULT_SENSITIVE_KEYS)]
        snippet = resp.get("body_snippet") or ""
        leaked: List[str] = []
        try:
            paths = _flatten(json.loads(snippet))
            leaked = sorted({p for p in paths
                             if any(s == p.split(".")[-1].lower() or s in p.lower() for s in keys)})
        except (ValueError, TypeError):
            # not JSON / truncated — fall back to a conservative substring scan
            low = snippet.lower()
            leaked = sorted({s for s in keys if f'"{s}"' in low})
        return {"vuln_class": "excessive_data_exposure", "target": u, "authorized": True,
                "poc_only": True, "status": resp.get("status"),
                "content_type": resp.get("content_type"),
                "leaked_sensitive_fields": leaked, "confirmed": bool(leaked),
                "verdict": "confirmed" if leaked else "refuted",
                "note": "sensitive field names returned to the client (values redacted here)",
                "advisory": True}
