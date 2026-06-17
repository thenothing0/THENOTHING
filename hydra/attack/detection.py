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

from hydra.attack.two_signal import Signal

CONFIRMED, SUSPECTED, REFUTED = "confirmed", "suspected", "refuted"

_REFLECTION_CLASSES = {"xss", "crlf", "open_redirect"}
_LFI_MARKERS = ["root:x:0:0", "root:!:0:0", "[boot loader]", "; for 16-bit app support",
                "daemon:x:", "/bin/bash"]
_SQL_ERRORS = ["you have an error in your sql syntax", "warning: mysql", "unclosed quotation mark",
               "quoted string not properly terminated", "pg_query", "psql:", "ora-0", "sqlite3.",
               "sqlstate[", "odbc sql server driver", "supplied argument is not a valid mysql"]
_NOSQL_ERRORS = ["mongoerror", "mongo error", "bson", "$where", "unexpected token",
                 "syntaxerror: unexpected", "cast to objectid failed", "e11000",
                 "command failed with error", "couchdberror"]
_LDAP_ERRORS = ["ldapexception", "javax.naming", "invalid dn syntax", "ldap_search",
                "ldap: error code", "com.sun.jndi.ldap", "protocol error", "bad search filter"]
# benign marker embedded in the prototype-pollution PoC payloads.
_PP_MARKER = "hydrapp"
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

        if vc == "nosqli" and any(e in body for e in _NOSQL_ERRORS):
            return CONFIRMED, "NoSQL error signature in response", signals

        if vc == "ldapi" and any(e in body for e in _LDAP_ERRORS):
            return CONFIRMED, "LDAP error signature in response", signals

        if vc == "prototype_pollution" and _PP_MARKER in body and _PP_MARKER not in base_body:
            return CONFIRMED, "polluted prototype property reflected only under injection", signals

        # weak differential: status flip or large length delta → worth a manual look
        if resp.get("status") != baseline.get("status"):
            return SUSPECTED, "status differs from baseline", signals
        bl = baseline.get("length") or 0
        if bl and abs((resp.get("length") or 0) - bl) > max(40, 0.25 * bl):
            return SUSPECTED, "response length differs materially from baseline", signals
        return REFUTED, "no differential signal vs baseline", signals


    def signals(self, vuln_class: str, baseline: Dict, payload: str, resp: Dict) -> List[Signal]:
        """All INDEPENDENT signals present in a response (feeds TwoSignalConfirmer). Reflection is
        content-type aware: a payload echoed into a JSON/non-markup response is NOT an XSS signal."""
        vc = (vuln_class or "").lower()
        body, base = _body(resp), _body(baseline)
        ct = (resp.get("content_type") or "").lower()
        out: List[Signal] = []
        if not resp.get("executed"):
            return out
        html_ctx = ("html" in ct or "javascript" in ct or "xml" in ct or not ct)
        if payload and payload.lower() in body and payload.lower() not in base:
            if vc not in _REFLECTION_CLASSES:
                pass
            elif vc == "xss" and not html_ctx:
                pass                                       # reflected into JSON/plain → not XSS
            else:
                out.append(Signal("reflection", f"payload echoed unescaped ({ct or 'no ct'})"))
        if vc in ("lfi", "path_traversal") and any(m in body for m in _LFI_MARKERS):
            out.append(Signal("file_marker", "file-content marker (e.g. /etc/passwd)"))
        if vc == "ssti" and "49" in body and "49" not in base:
            out.append(Signal("marker", "template expression evaluated (7*7=49)"))
        if vc == "sqli":
            if any(e in body for e in _SQL_ERRORS):
                out.append(Signal("error_signature", "database error signature"))
            if (resp.get("elapsed_ms") or 0) >= _TIME_BLIND_MS and \
                    (baseline.get("elapsed_ms") or 0) < _TIME_BLIND_MS:
                out.append(Signal("timing", "time-based delay vs fast baseline"))
        if vc == "open_redirect":
            loc = resp.get("location") or ""
            if loc and (payload.strip("/") in loc or "evil.example.com" in loc):
                out.append(Signal("redirect_location", "redirect Location points off-host"))
        if vc == "nosqli" and any(e in body for e in _NOSQL_ERRORS):
            out.append(Signal("error_signature", "NoSQL error signature"))
        if vc == "ldapi" and any(e in body for e in _LDAP_ERRORS):
            out.append(Signal("error_signature", "LDAP error signature"))
        if vc == "prototype_pollution" and _PP_MARKER in body and _PP_MARKER not in base:
            out.append(Signal("marker", "polluted prototype property reflected under injection"))
        if resp.get("status") != baseline.get("status"):
            out.append(Signal("differential_status",
                              f"{baseline.get('status')}->{resp.get('status')}"))
        bl = baseline.get("length") or 0
        if bl and abs((resp.get("length") or 0) - bl) > max(40, 0.25 * bl):
            out.append(Signal("differential_length", "response length delta vs baseline"))
        if resp.get("dom_executed"):                       # attached by BrowserConfirmer
            out.append(Signal("dom_execution", "headless-browser JS execution"))
        if resp.get("oob_confirmed"):                      # attached by OOBConfirmer
            out.append(Signal("oob_callback", "out-of-band interaction received"))
        return out

    def boolean_blind(self, true_resp: Dict, false_resp: Dict) -> Tuple[bool, str]:
        """Boolean-based blind SQLi: a TRUE-condition response that differs from the FALSE-condition
        response (status / length / body) is the most reliable blind signal."""
        if not (true_resp.get("executed") and false_resp.get("executed")):
            return False, "incomplete responses"
        if true_resp.get("status") != false_resp.get("status"):
            return True, "status differs (true vs false condition)"
        tl, fl = true_resp.get("length") or 0, false_resp.get("length") or 0
        if tl and abs(tl - fl) > max(24, 0.1 * tl):
            return True, "length differs (true vs false condition)"
        if _body(true_resp) and _body(true_resp) != _body(false_resp):
            return True, "body differs (true vs false condition)"
        return False, "no boolean differential"


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
