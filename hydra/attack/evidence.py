"""
PoC evidence capture (attack section, suggestion #6).

Bakes the operator's hard rule ("attach reproducible evidence to EVERY report") into the attack flow.
From a request/response exchange it produces a normalized `EvidenceBundle`: the request/response pair,
a copy-paste `curl` reproduction, a screenshot hook (wired to `hydra/browser` when available), and an
explicit confirmed-vs-suspected verdict. Deterministic, offline (the screenshot is an injectable hook,
not taken here). Formatting only — never sends traffic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlparse


def curl_repro(method: str, url: str, headers: Optional[Dict[str, str]] = None,
               body: str = "") -> str:
    """A deterministic, copy-paste curl reproduction (single-quoted, ordered headers)."""
    parts = ["curl", "-sk", "-X", method.upper(), f"'{url}'"]
    for k in sorted(headers or {}):
        parts += ["-H", f"'{k}: {headers[k]}'"]
    if body:
        parts += ["--data", f"'{body}'"]
    return " ".join(parts)


@dataclass
class EvidenceBundle:
    vuln_class: str
    target: str
    request: Dict
    response: Dict
    curl: str
    verdict: str                         # confirmed | suspected
    indicators: List[str] = field(default_factory=list)
    screenshot_path: str = ""
    notes: str = ""

    def to_dict(self) -> Dict:
        return {"vuln_class": self.vuln_class, "target": self.target,
                "request": self.request, "response": self.response, "curl": self.curl,
                "verdict": self.verdict, "indicators": self.indicators,
                "screenshot_path": self.screenshot_path, "notes": self.notes, "advisory": True}

    def render(self) -> str:
        """Report-ready evidence block (Markdown)."""
        lines = [f"### {self.vuln_class.upper()} — {self.verdict.upper()} ({self.target})",
                 "", "**Reproduction:**", "```bash", self.curl, "```",
                 f"**Response:** {self.response.get('status')} "
                 f"({self.response.get('length', '?')} bytes)"]
        if self.indicators:
            lines.append("**Indicators:** " + ", ".join(self.indicators))
        if self.screenshot_path:
            lines.append(f"**Screenshot:** {self.screenshot_path}")
        return "\n".join(lines)


class EvidenceCollector:
    def __init__(self, screenshot_hook=None):
        # screenshot_hook(url) -> path; default None (no headless browser invoked during build/tests)
        self._screenshot = screenshot_hook

    def capture(self, vuln_class: str, request: Dict, response: Dict,
                indicators: Optional[List[str]] = None, confirmed: Optional[bool] = None) -> EvidenceBundle:
        method = request.get("method", "GET")
        url = request.get("url", "")
        curl = curl_repro(method, url, request.get("headers"), request.get("body", ""))
        inds = list(indicators or [])
        # default verdict: confirmed when explicit, else inferred from indicators present
        verdict = ("confirmed" if (confirmed is True or (confirmed is None and inds))
                   else "suspected")
        shot = ""
        if self._screenshot and verdict == "confirmed":
            try:
                shot = self._screenshot(url) or ""
            except Exception:
                shot = ""
        return EvidenceBundle(vuln_class=vuln_class, target=urlparse(url).netloc or url,
                              request=request, response=response, curl=curl, verdict=verdict,
                              indicators=inds, screenshot_path=shot)

    @staticmethod
    def bypass_table(rows: List[Dict]) -> str:
        """Render the WAF-vs-Backend bypass table (Markdown) from waf_bypass.analyze() rows."""
        out = ["| Technique | Status | Length | Verdict |", "|---|---|---|---|"]
        for r in rows:
            out.append(f"| {r.get('technique')} | {r.get('status')} | "
                       f"{r.get('length','?')} | {r.get('verdict')} |")
        return "\n".join(out)
