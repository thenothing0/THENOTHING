"""
╔══════════════════════════════════════════════════════════════╗
║  Deception Detection Engine                                  ║
║  Honeypot detection, canary token detection, fake admin      ║
║  panel analysis, trap endpoint detection, deception scoring  ║
╚══════════════════════════════════════════════════════════════╝
"""

import logging
import re
import time
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger("hydra.deception")


@dataclass
class DeceptionIndicator:
    """An indicator of deceptive infrastructure."""
    indicator_type: str           # honeypot, canary, trap, fake_panel, decoy
    target: str
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    recommendation: str = ""
    timestamp: float = field(default_factory=time.time)


# ── Honeypot Signatures ──────────────────────

HONEYPOT_SIGNATURES = {
    "cowrie": {
        "indicators": ["SSH-2.0-OpenSSH_6.0p1", "cowrie"],
        "ports": [22, 2222, 23, 2323],
        "behavior": "Accepts any password, limited command set",
    },
    "kippo": {
        "indicators": ["SSH-2.0-OpenSSH_5.1p1"],
        "ports": [22, 2222],
        "behavior": "SSH honeypot with fake filesystem",
    },
    "dionaea": {
        "indicators": ["smbd", "ftpd", "httpd"],
        "ports": [21, 80, 135, 443, 445, 1433, 3306],
        "behavior": "Multi-protocol honeypot, accepts malware",
    },
    "glastopf": {
        "indicators": ["glastopf", "PHP/5."],
        "ports": [80, 8080],
        "behavior": "Web honeypot, responds to vulnerability scans",
    },
    "conpot": {
        "indicators": ["ICS", "SCADA", "Modbus"],
        "ports": [502, 102, 47808, 44818],
        "behavior": "ICS/SCADA honeypot",
    },
    "honeyd": {
        "indicators": [],
        "ports": [],
        "behavior": "Virtual honeypot, emulates OS fingerprints",
    },
}

# ── Canary Token Patterns ────────────────────

CANARY_PATTERNS = [
    r"canarytokens\.com",
    r"[a-z0-9]{32}\.canarytokens\.",
    r"o3n\.io",
    r"thinkst\.com",
    r"dnslog\.(cn|io|link)",
    r"burp(collaborator|suite)",
    r"interact\.sh",
    r"oast\.(fun|live|me|pro|site|online)",
    r"webhook\.site",
    r"requestbin\.(com|net)",
    r"pipedream\.net",
]

# ── Fake Admin Panel Indicators ──────────────

FAKE_ADMIN_INDICATORS = [
    "Login form with no CSRF token and generic error messages",
    "Admin panel responding on unusual port with default template",
    "Login page that accepts any credentials but never grants access",
    "Admin page with suspiciously generic content",
    "Panel with placeholder text or Lorem Ipsum",
]

TRAP_ENDPOINT_PATTERNS = [
    r"/admin/debug",
    r"/\.env\.backup",
    r"/wp-admin\.php",
    r"/server-status\.html",
    r"/phpmyadmin\.bak",
    r"/api/internal/debug",
    r"/robots\.txt\.bak",
    r"/_debug/",
]


class DeceptionDetectionEngine:
    """
    Deception-aware reconnaissance engine.

    Detects:
      - Honeypots (Cowrie, Kippo, Dionaea, Glastopf, Conpot)
      - Canary tokens in responses and DNS
      - Fake admin panels designed to waste attacker time
      - Trap endpoints that trigger alerts
      - Decoy services and deception infrastructure

    Reduces interaction with deceptive systems to:
      - Minimize noisy workflows
      - Avoid triggering SOC alerts
      - Preserve operational stealth
    """

    def __init__(self):
        self._indicators: List[DeceptionIndicator] = []
        self._deception_scores: Dict[str, float] = {}
        self._safe_targets: set = set()
        self._unsafe_targets: set = set()

    def analyze_target(self, target: str, response_data: Dict[str, Any]) -> DeceptionIndicator:
        """Analyze a target for deception indicators."""
        evidence = []
        score = 0.0

        # Check honeypot signatures
        hp_score = self._check_honeypot(target, response_data)
        if hp_score > 0:
            score += hp_score
            evidence.append(f"Honeypot indicators detected (score: {hp_score:.2f})")

        # Check canary tokens
        canary_found = self._check_canary_tokens(response_data)
        if canary_found:
            score += 0.8
            evidence.extend(canary_found)

        # Check fake admin panel
        fake_panel = self._check_fake_admin(response_data)
        if fake_panel:
            score += 0.5
            evidence.extend(fake_panel)

        # Check trap endpoints
        trap = self._check_trap_endpoints(target)
        if trap:
            score += 0.6
            evidence.extend(trap)

        # Behavioral anomalies
        anomalies = self._check_behavioral_anomalies(response_data)
        if anomalies:
            score += len(anomalies) * 0.15
            evidence.extend(anomalies)

        confidence = min(score, 1.0)
        self._deception_scores[target] = confidence

        indicator = DeceptionIndicator(
            indicator_type="composite",
            target=target,
            confidence=confidence,
            evidence=evidence,
            recommendation=self._recommend(confidence),
        )

        if confidence > 0.3:
            self._indicators.append(indicator)
            self._unsafe_targets.add(target)
            logger.warning(f"🎭 Deception detected: {target} (confidence={confidence:.2f})")
        else:
            self._safe_targets.add(target)

        return indicator

    def is_safe(self, target: str) -> bool:
        """Check if a target is considered safe (not deceptive)."""
        return self._deception_scores.get(target, 0.0) < 0.3

    def get_deception_score(self, target: str) -> float:
        """Get deception score for a target (0=safe, 1=definitely deceptive)."""
        return self._deception_scores.get(target, 0.0)

    # ── Detection Methods ─────────────────────

    def _check_honeypot(self, target: str,
                         response_data: Dict[str, Any]) -> float:
        score = 0.0
        headers = response_data.get("headers", {})
        banner = response_data.get("banner", "")
        ports = response_data.get("open_ports", [])

        server = headers.get("server", "").lower()
        combined = f"{server} {banner}".lower()

        for hp_name, hp_info in HONEYPOT_SIGNATURES.items():
            for indicator in hp_info["indicators"]:
                if indicator.lower() in combined:
                    score += 0.4
                    break
            # Suspicious port combinations
            if hp_info["ports"]:
                matching_ports = set(ports) & set(hp_info["ports"])
                if len(matching_ports) >= 3:
                    score += 0.3

        # Generic honeypot indicators
        if response_data.get("accepts_any_password"):
            score += 0.5
        if response_data.get("too_many_open_ports", False):
            score += 0.3
        if len(ports) > 20:
            score += 0.2

        return min(score, 1.0)

    def _check_canary_tokens(self, response_data: Dict[str, Any]) -> List[str]:
        found = []
        body = response_data.get("body", "")
        headers_str = str(response_data.get("headers", {}))
        combined = f"{body} {headers_str}"

        for pattern in CANARY_PATTERNS:
            if re.search(pattern, combined, re.IGNORECASE):
                found.append(f"Canary token pattern detected: {pattern}")

        return found

    def _check_fake_admin(self, response_data: Dict[str, Any]) -> List[str]:
        issues = []
        body = response_data.get("body", "").lower()
        status = response_data.get("status_code", 200)
        headers = response_data.get("headers", {})

        # Generic login that always fails
        if status == 200 and "login" in body:
            if "csrf" not in body and "token" not in body:
                issues.append("Login form without CSRF protection — possible fake panel")
            if "lorem ipsum" in body or "placeholder" in body:
                issues.append("Placeholder content in admin panel — likely decoy")

        # Suspiciously easy-to-find admin
        url = response_data.get("url", "")
        if any(p in url.lower() for p in ["/admin", "/administrator", "/wp-admin"]):
            if not headers.get("set-cookie"):
                issues.append("Admin page with no session management — suspicious")

        return issues

    def _check_trap_endpoints(self, target: str) -> List[str]:
        traps = []
        for pattern in TRAP_ENDPOINT_PATTERNS:
            if re.search(pattern, target, re.IGNORECASE):
                traps.append(f"Trap endpoint pattern: {pattern}")
        return traps

    def _check_behavioral_anomalies(self,
                                     response_data: Dict[str, Any]) -> List[str]:
        anomalies = []
        status = response_data.get("status_code", 200)
        response_time = response_data.get("response_time_ms", 0)
        body_length = response_data.get("content_length", 0)

        # Suspiciously fast responses for complex pages
        if response_time < 5 and body_length > 10000:
            anomalies.append("Suspiciously fast response for large body — pre-generated content")

        # Identical responses to different inputs
        if response_data.get("identical_error_responses"):
            anomalies.append("Identical error responses — may indicate honeypot")

        # Server version mismatch
        headers = response_data.get("headers", {})
        server = headers.get("server", "")
        if "Apache" in server and "IIS" in str(headers):
            anomalies.append("Server header mismatch — possible emulated environment")

        return anomalies

    def _recommend(self, confidence: float) -> str:
        if confidence > 0.8:
            return "AVOID — high deception probability, do not interact"
        if confidence > 0.5:
            return "CAUTION — moderate deception indicators, minimal interaction"
        if confidence > 0.3:
            return "MONITOR — some suspicious patterns, proceed carefully"
        return "SAFE — no significant deception indicators"

    def filter_safe_targets(self, targets: List[str]) -> List[str]:
        """Filter a list of targets, removing deceptive ones."""
        return [t for t in targets if self.is_safe(t)]

    def get_summary(self) -> Dict[str, Any]:
        return {
            "analyzed_targets": len(self._deception_scores),
            "deceptive_targets": len(self._unsafe_targets),
            "safe_targets": len(self._safe_targets),
            "total_indicators": len(self._indicators),
        }
