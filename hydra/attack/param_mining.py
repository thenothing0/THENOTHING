"""
Parameter & endpoint mining (improvement #2 — multiplies the value of every scanner).

The injection scanners only test the injection points they can SEE (existing params, JSON keys, path
segments). The highest-yield hidden surface is the parameters and endpoints that aren't in the request
you started from. This module discovers them and hands distinct, injectable endpoints back to the
scanner:

  * `ParameterMiner` (gated, uses the executor) — Arjun-style reflection-based discovery: send batches
    of candidate parameter names carrying a unique canary, and when the canary is reflected (or the
    response changes materially vs baseline) isolate the responsible parameter with a per-parameter
    confirm pass. Bounded request budget; deny-by-default.
  * `JSEndpointExtractor` (pure, network-free) — extract endpoints, parameter names, and high-signal
    secrets from JavaScript bodies (the other big source of hidden surface). No I/O.

PoC-only (a benign canary value; reads responses only). Deterministic given the executor.
"""

from __future__ import annotations

import hashlib
import re
from typing import Dict, List, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

# A compact, high-signal default parameter wordlist (operator can extend / replace).
DEFAULT_PARAM_WORDLIST = [
    "id", "user", "user_id", "uid", "account", "page", "q", "query", "search", "s", "name",
    "email", "url", "redirect", "redirect_uri", "next", "return", "callback", "file", "path",
    "dir", "lang", "locale", "format", "type", "category", "sort", "order", "filter", "fields",
    "token", "api_key", "key", "access", "role", "admin", "debug", "test", "preview", "draft",
    "include", "template", "view", "action", "cmd", "exec", "data", "json", "xml", "ref", "src",
]

# endpoints/paths and URLs in JS source.
_PATH_RE = re.compile(r"""['"`](/[A-Za-z0-9_\-./]{1,180}|https?://[^'"`\s]{1,200})['"`]""")
# fetch/axios/XHR-style calls.
_FETCH_RE = re.compile(r"""(?:fetch|axios\.\w+|\.open)\s*\(\s*['"`]([^'"`]{1,200})['"`]""")
# parameter names: ?a=, &b=, searchParams.get('x'), getParameter("y"), params:{z:..}
_PARAM_RE = re.compile(r"""[?&]([A-Za-z0-9_\-]{1,40})=|"""
                       r"""(?:searchParams\.get|getParameter|get)\(\s*['"`]([A-Za-z0-9_\-]{1,40})['"`]""")
# modest high-signal secret patterns (NOT exhaustive — flags obvious leaks in JS bundles).
_SECRET_RES = [
    ("aws_access_key", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    ("google_api_key", re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b")),
    ("slack_token", re.compile(r"\b(xox[baprs]-[0-9A-Za-z\-]{10,})\b")),
    ("bearer_jwt", re.compile(r"\b(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{6,})\b")),
    ("generic_api_key", re.compile(r"""['"]?(?:api[_-]?key|secret|token)['"]?\s*[:=]\s*['"]([A-Za-z0-9_\-]{16,})['"]""", re.I)),
]


def _with_params(url: str, params: Dict[str, str]) -> str:
    p = urlparse(url if "://" in url else f"https://{url}")
    q = dict(parse_qsl(p.query, keep_blank_values=True))
    q.update(params)
    return urlunparse(p._replace(query=urlencode(q)))


class ParameterMiner:
    def __init__(self, gate=None, executor=None):
        if gate is None:
            from hydra.authorization import BugBountyAuthorizationGate
            gate = BugBountyAuthorizationGate()
        self.gate = gate
        if executor is None:
            from hydra.attack_runtime import HttpExecutor
            executor = HttpExecutor(gate=gate)
        self.executor = executor

    def mine(self, url: str, session=None, wordlist: Optional[List[str]] = None,
             batch: int = 20, max_requests: int = 80) -> Dict:
        d = self.gate.authorize(url, "exploitation")
        if not d.authorized:
            return {"authorized": False, "reason": d.reason, "advisory": True}
        words = [w for w in (wordlist or DEFAULT_PARAM_WORDLIST) if w]
        canary = "hydrap" + hashlib.sha1(url.encode()).hexdigest()[:6]

        def _get(params: Dict[str, str]) -> Dict:
            req = {"method": "GET", "url": _with_params(url, params), "headers": {}}
            return self.executor(session.apply(req) if session is not None else req)

        baseline = _get({})
        base_len = baseline.get("length") or 0
        budget = max(1, max_requests)
        budget -= 1
        discovered: List[Dict] = []
        seen = set()

        for i in range(0, len(words), max(1, batch)):
            if budget <= 0:
                break
            chunk = words[i:i + batch]
            resp = _get({w: canary for w in chunk})
            budget -= 1
            body = resp.get("body_snippet") or ""
            reflected = canary in body
            len_delta = base_len and abs((resp.get("length") or 0) - base_len) > max(40, 0.25 * base_len)
            if not (reflected or len_delta):
                continue
            # isolate the responsible parameter(s) with a per-parameter confirm pass.
            for w in chunk:
                if budget <= 0 or w in seen:
                    break
                r = _get({w: canary})
                budget -= 1
                b = r.get("body_snippet") or ""
                if canary in b:
                    discovered.append({"param": w, "signal": "reflected",
                                       "detail": "canary value echoed in response"})
                    seen.add(w)
                elif base_len and abs((r.get("length") or 0) - base_len) > max(40, 0.25 * base_len):
                    discovered.append({"param": w, "signal": "behavioral",
                                       "detail": "response changed materially vs baseline"})
                    seen.add(w)
        injectable = [_with_params(url, {x["param"]: ""}) for x in discovered]
        return {"target": url, "authorized": True, "poc_only": True,
                "candidates_tested": len(words), "requests_used": max_requests - budget,
                "discovered": discovered, "discovered_count": len(discovered),
                "injectable_endpoints": injectable,
                "note": "feed injectable_endpoints to attack_scan_crawled to scan the hidden surface",
                "advisory": True}


class JSEndpointExtractor:
    """Pure extraction of endpoints / parameters / secrets from JavaScript source."""

    def extract(self, js_text: str) -> Dict:
        text = js_text or ""
        endpoints = set()
        for m in _PATH_RE.finditer(text):
            endpoints.add(m.group(1))
        for m in _FETCH_RE.finditer(text):
            endpoints.add(m.group(1))
        params = set()
        for a, b in _PARAM_RE.findall(text):
            if a:
                params.add(a)
            if b:
                params.add(b)
        secrets = []
        for kind, rx in _SECRET_RES:
            for m in rx.finditer(text):
                val = m.group(1)
                secrets.append({"kind": kind, "value_preview": val[:6] + "…" + val[-2:]
                                if len(val) > 12 else "***"})
        # endpoints that already declare query params are immediately injectable.
        return {"endpoints": sorted(endpoints), "params": sorted(params),
                "secrets": secrets, "endpoint_count": len(endpoints),
                "param_count": len(params), "secret_count": len(secrets),
                "note": "secrets are previews only (values redacted); validate before reporting",
                "advisory": True}
