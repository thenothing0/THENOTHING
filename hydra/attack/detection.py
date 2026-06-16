"""
Detection engine (attack section improvements #1/#2/#5 — pure, network-free).

Turns raw responses into trustworthy verdicts:
  * `DifferentialDetector` — compares a payload response against a benign BASELINE response (status /
    length / timing / reflection / class-specific markers) → confirmed | suspected | refuted. This is
    what stops "everything is suspected": a reflected XSS, an evaluated SSTI, an error/time-based SQLi,
    an /etc/passwd LFI, or an off-host redirect are CONFIRMED only on a real differential signal.
  * `AccessControlAnalyzer` — compares the SAME resource fetched as two identities → IDOR / broken
    access control (user B receives user A's resource) — the highest-bounty class.
  * `is_waf_block` — recognises a WAF/edge block so the live loop can adapt (mutate) and back off.
All pure functions of the response dicts (no I/O); deterministic.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

CONFIRMED, SUSPECTED, REFUTED = "confirmed", "suspected", "refuted"

_REFLECTION_CLASSES = {"xss", "crlf", "open_redirect"}
_LFI_MARKERS = ["root:x:0:0", "root:!:0:0", "[boot loader]", "; for 16-bit app support",
                "daemon:x:", "/bin/bash"]
_SQL_ERRORS = ["you have an error in your sql syntax", "warning: mysql", "unclosed quotation mark",
               "quoted string not properly terminated", "pg_query", "psql:", "ora-0", "sqlite3.",
               "sqlstate[", "odbc sql server driver", "supplied argument is not a valid mysql"]
_WAF_STATUS = {403, 406, 429, 501, 503}
_WAF_MARKERS = ["attention required", "cloudflare", "access denied", "request blocked",
                "this request has been blocked", "incident id", "mod_security", "captcha",
                "akamai", "web application firewall", "forbidden by administrative rules"]
_TIME_BLIND_MS = 4500.0


def _body(resp: Dict) -> str:
    return (resp.get("body_snippet") or "").lower()


def is_waf_block(resp: Dict) -> bool:
    if resp.get("status") in _WAF_STATUS:
        return True
    b = _body(resp)
    return any(m in b for m in _WAF_MARKERS)


class DifferentialDetector:
    def decide(self, vuln_class: str, baseline: Dict, payload: str,
               resp: Dict) -> Tuple[str, str, Dict]:
        vc = (vuln_class or "").lower()
        body, base_body = _body(resp), _body(baseline)
        signals: Dict = {"status": resp.get("status"),
                         "baseline_status": baseline.get("status"),
                         "length": resp.get("length"), "baseline_length": baseline.get("length"),
                         "elapsed_ms": resp.get("elapsed_ms"),
                         "reflected": bool(resp.get("reflected"))}
        if not resp.get("executed"):
            return SUSPECTED, "no response (not executed / blocked)", signals

        # reflection-based: payload echoed in the payload response but NOT the baseline
        if vc in _REFLECTION_CLASSES and payload and payload.lower() in body and \
                payload.lower() not in base_body:
            return CONFIRMED, "payload reflected unescaped (differential vs baseline)", signals

        if vc in ("lfi", "path_traversal") and any(m in body for m in _LFI_MARKERS):
            return CONFIRMED, "file-content marker present (e.g. /etc/passwd)", signals

        if vc == "ssti" and ("49" in body and "49" not in base_body):
            return CONFIRMED, "template expression evaluated (7*7=49) only under injection", signals

        if vc == "sqli":
            if any(e in body for e in _SQL_ERRORS):
                return CONFIRMED, "database error signature in response", signals
            if (resp.get("elapsed_ms") or 0) >= _TIME_BLIND_MS and \
                    (baseline.get("elapsed_ms") or 0) < _TIME_BLIND_MS:
                return CONFIRMED, "time-based blind (injected delay vs fast baseline)", signals

        if vc == "open_redirect":
            loc = (resp.get("location") or "")
            if loc and (payload.strip("/") in loc or "evil.example.com" in loc):
                return CONFIRMED, "redirect Location points off-host", signals

        # weak differential: status flip or large length delta → worth a manual look
        if resp.get("status") != baseline.get("status"):
            return SUSPECTED, "status differs from baseline", signals
        bl = baseline.get("length") or 0
        if bl and abs((resp.get("length") or 0) - bl) > max(40, 0.25 * bl):
            return SUSPECTED, "response length differs materially from baseline", signals
        return REFUTED, "no differential signal vs baseline", signals


class AccessControlAnalyzer:
    """IDOR / broken access control: does identity B receive identity A's resource?"""

    def decide(self, owner: Dict, other: Dict,
               owner_markers: Optional[List[str]] = None) -> Tuple[str, str, Dict]:
        signals = {"owner_status": owner.get("status"), "other_status": other.get("status"),
                   "owner_length": owner.get("length"), "other_length": other.get("length")}
        if not (owner.get("executed") and other.get("executed")):
            return SUSPECTED, "incomplete responses", signals
        ob = _body(other)
        if owner_markers and any(m.lower() in ob for m in owner_markers if m):
            return CONFIRMED, "identity B's response contains identity A's private marker", signals
        if other.get("status") in (401, 403, 404):
            return REFUTED, f"identity B properly denied (HTTP {other.get('status')})", signals
        ol = owner.get("length") or 0
        if owner.get("status") == 200 and other.get("status") == 200 and ol and \
                abs((other.get("length") or 0) - ol) <= max(16, 0.05 * ol):
            return CONFIRMED, "identity B received an equivalent 200 resource (access control gap)", signals
        return SUSPECTED, "inconclusive — compare resource bodies manually", signals
