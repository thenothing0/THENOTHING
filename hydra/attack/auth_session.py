"""
CSRF / cookie-security / password-reset-poisoning testers (improvement #4 — the classic auth gaps).

The last untested high-yield authentication classes:

  * `CSRFTester` (gated, executor) — for a state-changing request, replays it WITHOUT the anti-CSRF
    token, with a SWAPPED/invalid token, and from a cross-origin Origin/Referer. If the server still
    performs the action (2xx, not an auth/redirect rejection) the endpoint lacks CSRF protection; two
    independent acceptances (no-token + cross-origin) corroborate.
  * `CookieAuditor` (pure) — parses `Set-Cookie` headers and flags missing Secure / HttpOnly /
    SameSite, `SameSite=None` without Secure, and over-broad Domain/Path on session cookies.
  * `PasswordResetPoisoning` (gated, executor) — submits the reset flow with a tampered
    Host / X-Forwarded-Host / X-Forwarded-Server; if the attacker host is reflected (the reset link
    would point at it) that's account-takeover-grade host-header poisoning.

Gated (deny-by-default), PoC-only (a benign reset for an operator-chosen address; no token is ever
stolen). Network only via the injected executor. Deterministic.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

_AUTH_REJECT = {401, 403}                                  # an auth/permission rejection
_SAMESITE_RE = re.compile(r"samesite=(\w+)", re.I)
_DOMAIN_RE = re.compile(r"domain=([^;]+)", re.I)


def _accepted(resp: Dict) -> bool:
    """A state-changing request looks ACCEPTED when it returns 2xx and isn't an auth rejection."""
    st = resp.get("status") or 0
    return resp.get("executed") and (st // 100 == 2) and st not in _AUTH_REJECT


class CSRFTester:
    def __init__(self, gate=None, executor=None):
        if gate is None:
            from hydra.authorization import BugBountyAuthorizationGate
            gate = BugBountyAuthorizationGate()
        self.gate = gate
        if executor is None:
            from hydra.attack_runtime import HttpExecutor
            executor = HttpExecutor(gate=gate)
        self.executor = executor

    def test(self, request: Dict, csrf_field: str = "", csrf_header: str = "", session=None,
             evil_origin: str = "https://evil.example.com") -> Dict:
        url = request.get("url", "")
        decision = self.gate.authorize(url, "exploitation")
        if not decision.authorized:
            return {"authorized": False, "reason": decision.reason, "advisory": True}
        base = {"method": (request.get("method") or "POST").upper(), "url": url,
                "headers": dict(request.get("headers") or {}), "body": request.get("body", "")}
        if session is not None:
            base = session.apply(base)

        def _strip_token(req: Dict) -> Dict:
            r = {**req, "headers": dict(req.get("headers") or {})}
            if csrf_header:
                r["headers"].pop(csrf_header, None)
            if csrf_field and r.get("body"):
                r["body"] = re.sub(rf"(^|&){re.escape(csrf_field)}=[^&]*", "", r["body"]).lstrip("&")
            return r

        variants = {
            "no_token": _strip_token(base),
            "bad_token": {**base, "headers": {**base["headers"],
                                              **({csrf_header: "hydra-invalid"} if csrf_header else {})},
                          "body": (re.sub(rf"({re.escape(csrf_field)}=)[^&]*", r"\1hydra-invalid",
                                          base.get("body", "")) if csrf_field else base.get("body", ""))},
            "cross_origin": {**base, "headers": {**base["headers"], "Origin": evil_origin,
                                                 "Referer": evil_origin + "/"}},
        }
        rows = {}
        for name, req in variants.items():
            resp = self.executor(req)
            rows[name] = {"status": resp.get("status"), "accepted": _accepted(resp)}
        # confirmed when the action goes through without a valid token AND cross-origin (2 signals)
        signals = [n for n in ("no_token", "bad_token", "cross_origin") if rows[n]["accepted"]]
        confirmed = rows["no_token"]["accepted"] or rows["bad_token"]["accepted"]
        verdict = ("confirmed" if (confirmed and rows["cross_origin"]["accepted"])
                   else "suspected" if confirmed else "refuted")
        return {"vuln_class": "csrf", "target": url, "authorized": True, "poc_only": True,
                "results": rows, "accepting_variants": signals,
                "confirmed": verdict == "confirmed", "verdict": verdict,
                "note": "state-changing request accepted without a valid CSRF token (and cross-origin)",
                "advisory": True}


class CookieAuditor:
    """Pure audit of Set-Cookie security attributes."""

    def audit(self, set_cookie_headers: List[str]) -> Dict:
        rows: List[Dict] = []
        for raw in set_cookie_headers or []:
            low = raw.lower()
            name = raw.split("=", 1)[0].strip()
            issues = []
            if "secure" not in low:
                issues.append("missing Secure")
            if "httponly" not in low:
                issues.append("missing HttpOnly")
            m = _SAMESITE_RE.search(low)
            if not m:
                issues.append("missing SameSite")
            elif m.group(1).lower() == "none" and "secure" not in low:
                issues.append("SameSite=None without Secure")
            dm = _DOMAIN_RE.search(low)
            if dm and dm.group(1).strip().startswith("."):
                issues.append(f"broad Domain ({dm.group(1).strip()})")
            sessiony = any(k in name.lower() for k in ("sess", "sid", "auth", "token", "jwt"))
            rows.append({"cookie": name, "issues": issues,
                         "session_cookie": sessiony,
                         "severity": "medium" if (sessiony and issues) else "low" if issues else "info"})
        flagged = [r for r in rows if r["issues"]]
        return {"vuln_class": "insecure_cookie", "cookies": rows, "flagged": flagged,
                "confirmed": bool(flagged), "advisory": True}


class PasswordResetPoisoning:
    _HEADERS = ["Host", "X-Forwarded-Host", "X-Forwarded-Server", "X-Host", "X-Forwarded-For"]

    def __init__(self, gate=None, executor=None):
        if gate is None:
            from hydra.authorization import BugBountyAuthorizationGate
            gate = BugBountyAuthorizationGate()
        self.gate = gate
        if executor is None:
            from hydra.attack_runtime import HttpExecutor
            executor = HttpExecutor(gate=gate)
        self.executor = executor

    def test(self, reset_url: str, email_field: str = "email", email: str = "victim@example.com",
             evil_host: str = "evil.example.com", json_body: bool = False) -> Dict:
        decision = self.gate.authorize(reset_url, "exploitation")
        if not decision.authorized:
            return {"authorized": False, "reason": decision.reason, "advisory": True}
        if json_body:
            import json as _json
            body = _json.dumps({email_field: email})
            ctype = "application/json"
        else:
            from urllib.parse import urlencode
            body = urlencode({email_field: email})
            ctype = "application/x-www-form-urlencoded"
        rows: List[Dict] = []
        for h in self._HEADERS:
            resp = self.executor({"method": "POST", "url": reset_url,
                                  "headers": {"Content-Type": ctype, h: evil_host},
                                  "body": body, "payload": evil_host})
            reflected = evil_host in (resp.get("body_snippet") or "")
            rows.append({"header": h, "status": resp.get("status"),
                         "attacker_host_reflected": reflected,
                         "verdict": "confirmed" if reflected else "suspected"})
        confirmed = [r for r in rows if r["attacker_host_reflected"]]
        return {"vuln_class": "password_reset_poisoning", "target": reset_url, "authorized": True,
                "poc_only": True, "results": rows, "confirmed": bool(confirmed),
                "confirmed_findings": confirmed,
                "note": "attacker host reflected → the reset link would point to attacker-controlled "
                        "infrastructure (account takeover)",
                "advisory": True}
