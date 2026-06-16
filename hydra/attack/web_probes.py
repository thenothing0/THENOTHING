"""
Web-class probes (attack section improvement #3 — pure request/response logic).

  * CORS              — reflect an attacker Origin + credentials (active, safe).
  * Cache poisoning   — DETECTION ONLY, with a BENIGN unique marker: does an unkeyed header reflect
                        AND get cached? It never stores malicious content (which would harm other
                        users — a hard prohibition); it only checks reflectability + cache headers.
  * Host header       — does an injected Host/X-Forwarded-Host reach the app (password-reset poisoning
                        / routing)?
  * Request smuggling — PLAN ONLY (advisory): emits the CL.TE / TE.CL probe methodology but does NOT
                        auto-send, because desync probes can corrupt OTHER users' requests on shared
                        infrastructure. Run it manually, carefully, on dedicated/authorized hosts.

Generators + analyzers only; the safe active probes execute through the gated executor.
"""

from __future__ import annotations

from typing import Dict, Tuple

EVIL_ORIGIN = "https://evil.example.com"


class CORSProbe:
    def request(self, url: str, origin: str = EVIL_ORIGIN) -> Dict:
        return {"method": "GET", "url": url, "headers": {"Origin": origin}}

    def analyze(self, resp: Dict, origin: str = EVIL_ORIGIN) -> Tuple[str, str]:
        if not resp.get("executed"):
            return "suspected", "no response"
        acao = (resp.get("acao") or resp.get("access_control_allow_origin") or "")
        acac = str(resp.get("acac") or resp.get("access_control_allow_credentials") or "").lower()
        body = resp.get("body_snippet") or ""
        # the executor exposes a few response headers; fall back to body inspection
        reflected = origin in acao or origin in body or acao == "*"
        if reflected and ("true" in acac or origin in acao):
            return ("confirmed", "Origin reflected with credentials — cross-origin data theft")
        if reflected:
            return "suspected", "Origin reflected (check credentialed responses)"
        return "suspected", "no CORS reflection"


class CachePoisonProbe:
    """Detection-only: benign marker, never stores attacker content."""

    def request(self, url: str, marker: str = "hydracachemarker") -> Dict:
        return {"method": "GET", "url": url,
                "headers": {"X-Forwarded-Host": f"{marker}.example", "X-Forwarded-Scheme": "nothttps"}}

    def analyze(self, resp: Dict, marker: str = "hydracachemarker") -> Tuple[str, str]:
        if not resp.get("executed"):
            return "suspected", "no response"
        body = resp.get("body_snippet") or ""
        cache_hdr = " ".join(str(resp.get(k, "")) for k in ("x_cache", "age", "cf_cache_status",
                                                            "content_type"))
        reflected = marker in body
        cached = any(s in cache_hdr.lower() for s in ("hit", "age"))
        if reflected and cached:
            return "confirmed", "unkeyed header reflected AND cached — cache-poisoning candidate"
        if reflected:
            return "suspected", "unkeyed header reflected (verify cacheability manually)"
        return "suspected", "no unkeyed-input reflection"


class HostHeaderProbe:
    def request(self, url: str, marker: str = "hydrahostmarker.example") -> Dict:
        return {"method": "GET", "url": url, "headers": {"X-Forwarded-Host": marker}}

    def analyze(self, resp: Dict, marker: str = "hydrahostmarker.example") -> Tuple[str, str]:
        if not resp.get("executed"):
            return "suspected", "no response"
        body = resp.get("body_snippet") or ""
        loc = resp.get("location") or ""
        if marker in body or marker in loc:
            return "confirmed", "injected Host reflected (password-reset poisoning / routing risk)"
        return "suspected", "injected Host not reflected"


class SmugglingPlan:
    """PLAN-ONLY: HTTP request-smuggling methodology. NOT auto-executed (co-tenant risk)."""

    def plan(self, url: str) -> Dict:
        return {
            "url": url,
            "techniques": [
                {"name": "CL.TE", "idea": "front-end uses Content-Length, back-end uses "
                 "Transfer-Encoding — smuggle a prefix that poisons the next request"},
                {"name": "TE.CL", "idea": "front-end uses Transfer-Encoding, back-end uses "
                 "Content-Length"},
                {"name": "TE.TE", "idea": "obfuscated Transfer-Encoding header both ends parse "
                 "differently"},
            ],
            "detection": "timing differential: a malformed TE/CL combo that makes the back-end wait "
                         "for more bytes delays the response vs a well-formed control",
            "warning": "ADVISORY ONLY — desync probes can corrupt OTHER users' requests on shared "
                       "infrastructure; run manually, with care, on authorized/dedicated hosts. Hydra "
                       "does NOT auto-send smuggling probes.",
            "advisory": True,
        }
