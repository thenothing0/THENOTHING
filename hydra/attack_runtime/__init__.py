"""
Attack Execution Runtime — the single NETWORK boundary for the attack section.

This package (deliberately separate from `hydra/attack/`, which stays provably network-free) holds the
real HTTP sender and the live bug-bounty scope loader. The executor is what actually puts PoC payloads
on the wire — so it is wrapped in safety rails:

  * GATED (defense-in-depth): it re-verifies the request's host against the bug-bounty authorization
    gate on every call and refuses anything not in-scope — even if the caller forgot to gate;
  * RATE-LIMITED: a minimum inter-request interval (no rapid-fire / DoS-shaped traffic);
  * BOUNDED: hard timeout, capped response read, redirects off by default;
  * PoC-ONLY: it carries the (already PoC-grade) payload and reads the response; it never escalates,
    exfiltrates, or repeats;
  * AUDITED: every send (and every refusal) is recorded.

`HttpExecutor` is injected into `hydra.attack.AttackWorkflow`. `ScopeLoader` fetches a program's
published scope (via the existing `hydra.scope.ScopePolicyEngine`) and registers it into the gate, so
"only bug-bounty sites" is sourced from the live program rather than hand-entered.
"""

from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.request
from typing import Dict, List
from urllib.parse import urlparse


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None          # do not auto-follow — observe 3xx (e.g. open-redirect Location) instead


class HttpExecutor:
    """Real, gated, rate-limited HTTP sender. Matches the `Callable[[Dict], Dict]` executor interface
    expected by `AttackWorkflow` (default there is the no-I/O `DryRunExecutor`)."""

    def __init__(self, gate=None, rate_per_sec: float = 1.0, timeout: float = 15.0,
                 max_body: int = 8192, allow_redirects: bool = False, verify_tls: bool = False,
                 user_agent: str = "hydra-poc/1.0 (authorized bug-bounty testing)"):
        if gate is None:
            from hydra.authorization import BugBountyAuthorizationGate
            gate = BugBountyAuthorizationGate()
        self.gate = gate                                  # always gated (deny-by-default)
        self.min_interval = (1.0 / rate_per_sec) if rate_per_sec > 0 else 0.0
        self.timeout = timeout
        self.max_body = max_body
        self.allow_redirects = allow_redirects
        self.user_agent = user_agent
        self._ctx = None if verify_tls else ssl._create_unverified_context()
        self._last = 0.0
        self._audit: List[Dict] = []

    def __call__(self, request: Dict) -> Dict:
        url = request.get("url", "")
        method = (request.get("method") or "GET").upper()
        headers = dict(request.get("headers") or {})
        payload = request.get("payload")
        body = request.get("body")

        # 1) GATE (defense-in-depth): re-verify the host is bug-bounty-authorized.
        decision = self.gate.authorize(url, "exploitation")
        if not decision.authorized:
            self._audit.append({"url": url, "executed": False, "blocked": True,
                                "reason": decision.reason, "ts": time.time()})
            return {"status": None, "length": 0, "executed": False, "blocked": True,
                    "reason": decision.reason}

        # 2) RATE LIMIT.
        if self.min_interval:
            dt = time.time() - self._last
            if dt < self.min_interval:
                time.sleep(self.min_interval - dt)

        # 3) SEND (bounded).
        data = body.encode("utf-8", "replace") if isinstance(body, str) else body
        headers.setdefault("User-Agent", self.user_agent)
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        opener = urllib.request.build_opener(
            *( [] if self.allow_redirects else [_NoRedirect()] ),
            urllib.request.HTTPSHandler(context=self._ctx))
        t0 = time.time()
        status, resp_headers, raw = None, {}, b""
        try:
            with opener.open(req, timeout=self.timeout) as r:
                status = getattr(r, "status", r.getcode())
                resp_headers = dict(r.headers or {})
                raw = r.read(self.max_body + 1)
        except urllib.error.HTTPError as e:                # 3xx (no-redirect) / 4xx / 5xx
            status = e.code
            resp_headers = dict(getattr(e, "headers", {}) or {})
            try:
                raw = e.read(self.max_body + 1)
            except Exception:
                raw = b""
        except Exception as e:
            self._last = time.time()
            self._audit.append({"url": url, "executed": False, "error": str(e), "ts": time.time()})
            return {"status": None, "length": 0, "executed": False, "error": str(e)}
        self._last = time.time()
        # Responsible WAF/rate back-off (#5): on 429/503 slow down before the next request (bounded),
        # so authorized testing never turns into rate-abuse; reset on a clean response.
        if status in (429, 503):
            self._backoff = min(((getattr(self, "_backoff", 0.0)) or (self.min_interval or 0.5)) * 2,
                                30.0)
            time.sleep(min(self._backoff, 5.0))
        else:
            self._backoff = 0.0

        text = raw[: self.max_body].decode("utf-8", "replace")
        reflected = bool(payload) and payload in text
        elapsed_ms = round((time.time() - t0) * 1000, 1)
        self._audit.append({"url": url, "method": method, "status": status,
                            "executed": True, "ts": time.time()})
        return {
            "status": status, "length": len(raw), "elapsed_ms": elapsed_ms,
            "reflected": reflected, "body_snippet": text[:512], "executed": True,
            "location": resp_headers.get("Location"),
            "content_type": resp_headers.get("Content-Type"),
        }

    def audit_log(self) -> List[Dict]:
        return list(self._audit)


class ScopeLoader:
    """Fetch a bug bounty program's scope and register it into the authorization gate."""

    def __init__(self, gate=None):
        if gate is None:
            from hydra.authorization import BugBountyAuthorizationGate
            gate = BugBountyAuthorizationGate()
        self.gate = gate

    def _register(self, scope) -> Dict:
        bp = self.gate.register_scope(scope)
        return {"registered": bp.to_dict(), "in_scope_assets": len(scope.in_scope),
                "out_of_scope_assets": len(scope.out_of_scope), "platform": scope.platform}

    def load_url(self, url: str, api_token: str = "") -> Dict:
        """LIVE: fetch a program's scope from its platform URL (HackerOne/Bugcrowd/…)."""
        import asyncio
        from hydra.scope import ScopePolicyEngine
        scope = asyncio.run(ScopePolicyEngine().load_from_url(url, api_token=api_token))
        return self._register(scope)

    def load_raw(self, platform: str, program_id: str, raw_scope: Dict) -> Dict:
        """OFFLINE: register from a raw scope dict (operator-provided / testable)."""
        import asyncio
        from hydra.scope import ScopePolicyEngine
        scope = asyncio.run(ScopePolicyEngine().load_scope(
            platform=platform, program_id=program_id, raw_scope=raw_scope))
        return self._register(scope)


def host_of(url: str) -> str:
    return (urlparse(url if "://" in url else f"https://{url}").hostname or "").lower()


from hydra.attack_runtime.confirm import BrowserConfirmer, OOBConfirmer  # noqa: E402
from hydra.attack_runtime.login import LoginError, LoginFlow  # noqa: E402
from hydra.attack_runtime.oob_client import InteractshPoller, OOBPoller  # noqa: E402
from hydra.attack_runtime.session import SessionContext, SessionManager  # noqa: E402

__all__ = ["HttpExecutor", "ScopeLoader", "host_of",
           "SessionContext", "SessionManager", "BrowserConfirmer", "OOBConfirmer",
           "OOBPoller", "InteractshPoller", "LoginFlow", "LoginError"]
