"""
Auth-protocol attacks (audit improvement #6) — OAuth/OIDC + SAML.

The attack section had CSRF-aware login but no PROTOCOL-level auth attacks. This adds the two highest-
value families:

  * `OAuthTester` (gated, uses the injected executor) — statically analyzes an authorize request for the
    classic weaknesses (missing `state` → login CSRF, missing PKCE `code_challenge`, implicit
    `response_type=token` token-in-fragment leakage, over-broad scope) and ACTIVELY tests
    `redirect_uri` validation by sending tampered variants and confirming when the server honours an
    attacker-controlled destination (the redirect_uri → open-redirect / token-theft primitive).
  * `SAMLAnalyzer` (local only, NOT gated — mirrors `JWTAnalyzer`) — decodes a SAML Response and flags
    unsigned / multi-assertion / comment-injection conditions, and GENERATES XSW (signature-wrapping)
    test vectors as advisory PoC artifacts. It does not auto-replay against an IdP (signature wrapping
    against live identity providers is delicate); generation + analysis only.

PoC-only: the OAuth redirect probe uses a benign attacker placeholder host and reads the response; it
never completes a token exchange or exfiltrates a code/token. Deterministic; `hydra/attack` stays
network-free except via the injected executor.
"""

from __future__ import annotations

import base64
import binascii
import re
from typing import Dict, List, Optional
from urllib.parse import parse_qs, parse_qsl, urlencode, urlparse, urlunparse

# OAuth scopes that are notably broad / sensitive when granted to a third party.
_BROAD_SCOPES = {"*", "all", "admin", "openid profile email offline_access", "read_write",
                 "user", "repo", "write", "delete"}


class OAuthTester:
    def __init__(self, executor=None, gate=None):
        if gate is None:
            from hydra.authorization import BugBountyAuthorizationGate
            gate = BugBountyAuthorizationGate()
        self.gate = gate
        self.executor = executor                          # gated HttpExecutor (or DryRunExecutor)

    def analyze(self, authorize_url: str) -> Dict:
        """Static analysis of an OAuth/OIDC authorize request (no network)."""
        p = urlparse(authorize_url)
        q = dict(parse_qsl(p.query, keep_blank_values=True))
        rt = (q.get("response_type") or "").lower()
        weaknesses: List[Dict] = []
        if "state" not in q or not q.get("state"):
            weaknesses.append({"issue": "missing_state", "severity": "medium",
                               "detail": "no `state` → authorization-code-flow login CSRF"})
        if "code" in rt and "code_challenge" not in q:
            weaknesses.append({"issue": "missing_pkce", "severity": "medium",
                               "detail": "code flow without PKCE `code_challenge` (code interception)"})
        if "token" in rt:
            weaknesses.append({"issue": "implicit_flow", "severity": "medium",
                               "detail": "`response_type=token` leaks tokens in the URL fragment"})
        scope = (q.get("scope") or "").strip().lower()
        if scope in _BROAD_SCOPES or scope.count(" ") >= 3:
            weaknesses.append({"issue": "broad_scope", "severity": "low",
                               "detail": f"broad/over-privileged scope requested: '{q.get('scope')}'"})
        return {"vuln_class": "oauth", "authorize_endpoint": urlunparse(p._replace(query="")),
                "params": sorted(q.keys()), "response_type": rt or None,
                "redirect_uri": q.get("redirect_uri"), "weaknesses": weaknesses,
                "advisory": True}

    def _variants(self, redirect_uri: str, evil: str) -> List[Dict]:
        """Tampered redirect_uri candidates (a representative, high-signal set)."""
        ev = urlparse(evil if "://" in evil else f"https://{evil}")
        ev_host = ev.hostname or "evil.example.com"
        out = [{"strategy": "full_replace", "value": evil}]
        if redirect_uri:
            o = urlparse(redirect_uri)
            base_host = o.hostname or ""
            out += [
                {"strategy": "subdomain_prefix", "value": urlunparse(
                    o._replace(netloc=f"{base_host}.{ev_host}"))},
                {"strategy": "at_trick", "value": f"{redirect_uri}@{ev_host}"},
                {"strategy": "path_append", "value": f"{redirect_uri.rstrip('/')}/.{ev_host}"},
                {"strategy": "open_redirect_param", "value": f"{redirect_uri}?next={evil}"},
            ]
        return out

    def test_redirect_uri(self, authorize_url: str, evil: str = "https://evil.example.com") -> Dict:
        """Send authorize requests with tampered `redirect_uri` and confirm when the server honours the
        attacker destination (3xx Location to the evil host, or it appears in a redirect). Gated."""
        d = self.gate.authorize(authorize_url, "exploitation")
        if not d.authorized:
            return {"authorized": False, "reason": d.reason, "advisory": True}
        if self.executor is None:
            return {"authorized": True, "error": "no executor injected", "advisory": True}
        p = urlparse(authorize_url)
        q = dict(parse_qsl(p.query, keep_blank_values=True))
        original = q.get("redirect_uri", "")
        ev_host = (urlparse(evil if "://" in evil else f"https://{evil}").hostname
                   or "evil.example.com")
        rows: List[Dict] = []
        for v in self._variants(original, evil):
            q2 = dict(q)
            q2["redirect_uri"] = v["value"]
            url = urlunparse(p._replace(query=urlencode(q2)))
            resp = self.executor({"method": "GET", "url": url, "headers": {}, "payload": ev_host})
            loc = resp.get("location") or ""
            honoured = bool(loc) and ev_host in (urlparse(loc).hostname or loc)
            rows.append({"strategy": v["strategy"], "redirect_uri": v["value"],
                         "status": resp.get("status"), "location": loc,
                         "honoured": honoured,
                         "verdict": "confirmed" if honoured else "suspected"})
        confirmed = [r for r in rows if r["honoured"]]
        return {"vuln_class": "oauth", "target": authorize_url, "authorized": True, "poc_only": True,
                "original_redirect_uri": original, "attacker_host": ev_host,
                "confirmed": bool(confirmed), "results": rows, "confirmed_findings": confirmed,
                "note": "server honoured an attacker-controlled redirect_uri → code/token theft",
                "advisory": True}


class SAMLAnalyzer:
    """Local SAML Response analysis + XSW test-vector generation (no network, not gated)."""

    _MAX = 1_000_000

    def _decode(self, saml_response: str) -> Optional[str]:
        s = (saml_response or "").strip()
        if "<" in s and "saml" in s.lower():
            return s                                       # already raw XML
        for variant in (s, s.replace("-", "+").replace("_", "/")):
            try:
                pad = variant + "=" * (-len(variant) % 4)
                xml = base64.b64decode(pad).decode("utf-8", "replace")
                if "<" in xml:
                    return xml
            except (binascii.Error, ValueError):
                continue
        return None

    def analyze(self, saml_response: str) -> Dict:
        xml = self._decode(saml_response)
        if not xml:
            return {"vuln_class": "saml", "error": "could not decode SAML Response (base64/XML)",
                    "advisory": True}
        if len(xml) > self._MAX:
            return {"vuln_class": "saml", "error": "SAML document too large to analyze",
                    "advisory": True}
        low = xml.lower()
        signatures = len(re.findall(r"<(?:ds:)?signature[\s>]", low))
        assertions = len(re.findall(r"<(?:saml2?:)?assertion[\s>]", low))
        weaknesses: List[Dict] = []
        if signatures == 0:
            weaknesses.append({"issue": "unsigned_assertion", "severity": "critical",
                               "detail": "no <Signature> → assertion can be forged/tampered"})
        if assertions > 1:
            weaknesses.append({"issue": "multiple_assertions", "severity": "high",
                               "detail": f"{assertions} assertions → signature-wrapping (XSW) risk"})
        if re.search(r"<!--", xml):
            weaknesses.append({"issue": "comment_in_xml", "severity": "medium",
                               "detail": "XML comments present → NameID comment-injection risk"})
        if signatures and assertions and ("signaturevalue" not in low):
            weaknesses.append({"issue": "incomplete_signature", "severity": "high",
                               "detail": "Signature element without SignatureValue"})
        return {"vuln_class": "saml", "signatures": signatures, "assertions": assertions,
                "weaknesses": weaknesses, "xsw_vectors": self.xsw_vectors(xml),
                "note": "analysis + advisory XSW test vectors only — not replayed against the IdP",
                "advisory": True}

    def xsw_vectors(self, xml: str) -> List[Dict]:
        """Describe XSW (signature-wrapping) test vectors as advisory PoC artifacts (no replay)."""
        return [
            {"name": "XSW1", "technique": "duplicate signed assertion, add a forged sibling assertion",
             "applies_when": "Response signature"},
            {"name": "XSW2", "technique": "wrap the signed assertion; place forged assertion as the "
                                          "processed one", "applies_when": "Assertion signature"},
            {"name": "XSW3", "technique": "forged assertion as the first child, signed assertion "
                                          "moved into it", "applies_when": "Assertion signature"},
            {"name": "comment_injection", "technique": "inject <!--x--> inside NameID to truncate the "
                                                       "canonicalized value", "applies_when": "any"},
        ]
