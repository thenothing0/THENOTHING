"""
╔══════════════════════════════════════════════════════════════╗
║  Stealth + OPSEC Intelligence Layer                          ║
║  Adaptive rate limiting, WAF-aware execution, behavioral     ║
║  mutation, traffic shaping, scan-noise minimization          ║
╚══════════════════════════════════════════════════════════════╝
"""

import asyncio
import logging
import random
import time
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger("hydra.stealth")


class StealthMode(str, Enum):
    AGGRESSIVE = "aggressive"     # Max speed, no stealth
    NORMAL = "normal"             # Balanced speed/stealth
    CAUTIOUS = "cautious"         # Reduced speed, moderate stealth
    STEALTH = "stealth"           # Low speed, high stealth
    GHOST = "ghost"               # Minimal footprint, max stealth


class ThreatLevel(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class StealthProfile:
    """Current stealth configuration."""
    mode: StealthMode = StealthMode.NORMAL
    threat_level: ThreatLevel = ThreatLevel.NONE
    request_delay_ms: int = 100
    max_requests_per_second: float = 10.0
    jitter_range_ms: Tuple = (50, 500)
    rotate_user_agents: bool = True
    rotate_headers: bool = True
    randomize_order: bool = True
    use_proxy_rotation: bool = False
    fingerprint_rotation: bool = True
    max_concurrent_requests: int = 3
    crawl_depth: int = 3
    payload_mutation_rate: float = 0.3


@dataclass
class BlockingIndicator:
    """An indicator that the target is blocking us."""
    indicator_type: str = ""      # rate_limit, waf_block, captcha, ip_ban, behavioral
    evidence: str = ""
    timestamp: float = field(default_factory=time.time)
    severity: ThreatLevel = ThreatLevel.LOW
    response_code: int = 0
    response_headers: Dict[str, str] = field(default_factory=dict)


# ── User-Agent Pool ───────────────────────────

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]

ACCEPT_HEADERS = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
]

ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9", "en-GB,en;q=0.9", "en-US,en;q=0.5",
    "en,en-US;q=0.9,en-GB;q=0.8", "en-US,en;q=0.9,es;q=0.8",
]


# ── Stealth Mode Profiles ────────────────────

MODE_PROFILES: Dict[StealthMode, Dict[str, Any]] = {
    StealthMode.AGGRESSIVE: {
        "request_delay_ms": 0, "max_rps": 100.0, "jitter": (0, 10),
        "rotate_ua": False, "rotate_headers": False,
        "max_concurrent": 20, "crawl_depth": 5, "mutation_rate": 0.0,
    },
    StealthMode.NORMAL: {
        "request_delay_ms": 100, "max_rps": 10.0, "jitter": (50, 300),
        "rotate_ua": True, "rotate_headers": True,
        "max_concurrent": 5, "crawl_depth": 3, "mutation_rate": 0.3,
    },
    StealthMode.CAUTIOUS: {
        "request_delay_ms": 500, "max_rps": 3.0, "jitter": (200, 1000),
        "rotate_ua": True, "rotate_headers": True,
        "max_concurrent": 2, "crawl_depth": 2, "mutation_rate": 0.5,
    },
    StealthMode.STEALTH: {
        "request_delay_ms": 2000, "max_rps": 1.0, "jitter": (1000, 5000),
        "rotate_ua": True, "rotate_headers": True,
        "max_concurrent": 1, "crawl_depth": 2, "mutation_rate": 0.7,
    },
    StealthMode.GHOST: {
        "request_delay_ms": 5000, "max_rps": 0.2, "jitter": (3000, 10000),
        "rotate_ua": True, "rotate_headers": True,
        "max_concurrent": 1, "crawl_depth": 1, "mutation_rate": 0.9,
    },
}


from typing import Tuple


class StealthEngine:
    """
    Adaptive stealth-aware offensive execution engine.

    Dynamically adapts:
      - Scan intensity based on defensive posture
      - Payload behavior based on WAF reactions
      - Recon depth based on blocking indicators
      - Execution timing with human-like jitter
      - Crawl aggressiveness based on rate limits
      - Header rotation to avoid fingerprinting
      - Request entropy to avoid pattern detection
    """

    def __init__(self, initial_mode: StealthMode = StealthMode.NORMAL):
        self._profile = StealthProfile(mode=initial_mode)
        self._blocking_indicators: List[BlockingIndicator] = []
        self._request_timestamps: List[float] = []
        self._escalation_count = 0
        self._apply_mode(initial_mode)

    @property
    def profile(self) -> StealthProfile:
        return self._profile

    # ── Mode Management ───────────────────────

    def set_mode(self, mode: StealthMode):
        """Set stealth mode and apply profile."""
        self._apply_mode(mode)
        logger.info(f"🕵️ Stealth mode: {mode.value} "
                     f"(delay={self._profile.request_delay_ms}ms, "
                     f"rps={self._profile.max_requests_per_second})")

    def _apply_mode(self, mode: StealthMode):
        """Apply a mode profile."""
        mp = MODE_PROFILES.get(mode, MODE_PROFILES[StealthMode.NORMAL])
        self._profile.mode = mode
        self._profile.request_delay_ms = mp["request_delay_ms"]
        self._profile.max_requests_per_second = mp["max_rps"]
        self._profile.jitter_range_ms = mp["jitter"]
        self._profile.rotate_user_agents = mp["rotate_ua"]
        self._profile.rotate_headers = mp["rotate_headers"]
        self._profile.max_concurrent_requests = mp["max_concurrent"]
        self._profile.crawl_depth = mp["crawl_depth"]
        self._profile.payload_mutation_rate = mp["mutation_rate"]

    # ── Adaptive Response ─────────────────────

    def record_blocking_indicator(self, indicator: BlockingIndicator):
        """Record a blocking indicator and auto-escalate stealth."""
        self._blocking_indicators.append(indicator)
        self._escalation_count += 1

        logger.warning(
            f"⚠️ Blocking indicator: {indicator.indicator_type} "
            f"(severity={indicator.severity.value})"
        )

        # Auto-escalate stealth mode
        if indicator.severity == ThreatLevel.CRITICAL:
            self.set_mode(StealthMode.GHOST)
        elif indicator.severity == ThreatLevel.HIGH:
            if self._profile.mode.value < StealthMode.STEALTH.value:
                self.set_mode(StealthMode.STEALTH)
        elif indicator.severity == ThreatLevel.MEDIUM:
            if self._profile.mode.value < StealthMode.CAUTIOUS.value:
                self.set_mode(StealthMode.CAUTIOUS)

        # Update threat level
        recent = [i for i in self._blocking_indicators
                  if time.time() - i.timestamp < 300]  # last 5 min
        if len(recent) >= 5:
            self._profile.threat_level = ThreatLevel.CRITICAL
        elif len(recent) >= 3:
            self._profile.threat_level = ThreatLevel.HIGH
        elif len(recent) >= 1:
            self._profile.threat_level = ThreatLevel.MEDIUM
        else:
            self._profile.threat_level = ThreatLevel.LOW

    def detect_blocking(self, status_code: int, headers: Dict[str, str],
                        body: str = "") -> Optional[BlockingIndicator]:
        """Detect if a response indicates blocking."""
        indicator = None

        # Rate limiting
        if status_code == 429:
            indicator = BlockingIndicator(
                indicator_type="rate_limit",
                evidence=f"HTTP 429, Retry-After: {headers.get('retry-after', 'N/A')}",
                severity=ThreatLevel.HIGH,
                response_code=status_code,
                response_headers=headers,
            )
        # WAF block
        elif status_code == 403:
            waf_headers = ["cf-ray", "x-sucuri-id", "x-akamai-transformed", "server"]
            waf_detected = any(h in headers for h in waf_headers)
            indicator = BlockingIndicator(
                indicator_type="waf_block" if waf_detected else "access_denied",
                evidence=f"HTTP 403{' (WAF detected)' if waf_detected else ''}",
                severity=ThreatLevel.HIGH if waf_detected else ThreatLevel.MEDIUM,
                response_code=status_code,
            )
        # CAPTCHA
        elif any(kw in body.lower() for kw in ["captcha", "challenge", "verify you are human"]):
            indicator = BlockingIndicator(
                indicator_type="captcha",
                evidence="CAPTCHA challenge detected in response",
                severity=ThreatLevel.HIGH,
            )
        # IP ban
        elif status_code in (0, 444, 503) and "retry-after" in headers:
            indicator = BlockingIndicator(
                indicator_type="ip_ban",
                evidence=f"HTTP {status_code} — possible IP ban",
                severity=ThreatLevel.CRITICAL,
            )

        if indicator:
            self.record_blocking_indicator(indicator)

        return indicator

    # ── Request Timing ────────────────────────

    async def wait_before_request(self):
        """Wait an appropriate amount of time before the next request."""
        base_delay = self._profile.request_delay_ms
        jitter_min, jitter_max = self._profile.jitter_range_ms
        jitter = random.randint(jitter_min, jitter_max)
        total_ms = base_delay + jitter

        # Enforce rate limit
        now = time.time()
        self._request_timestamps = [t for t in self._request_timestamps if now - t < 1.0]
        if len(self._request_timestamps) >= self._profile.max_requests_per_second:
            total_ms = max(total_ms, 1000)

        await asyncio.sleep(total_ms / 1000.0)
        self._request_timestamps.append(time.time())

    async def adjust_timing(self, cognitive_state):
        """Adjust timing based on cognitive state."""
        # If we've been blocked recently, slow down
        recent_blocks = len([i for i in self._blocking_indicators
                             if time.time() - i.timestamp < 60])
        if recent_blocks > 0:
            extra_delay = recent_blocks * 2000  # +2s per recent block
            await asyncio.sleep(extra_delay / 1000.0)

    # ── Header Generation ─────────────────────

    def get_stealth_headers(self) -> Dict[str, str]:
        """Generate stealth-rotated HTTP headers."""
        headers = {}
        if self._profile.rotate_user_agents:
            headers["User-Agent"] = random.choice(USER_AGENTS)
        else:
            headers["User-Agent"] = USER_AGENTS[0]

        if self._profile.rotate_headers:
            headers["Accept"] = random.choice(ACCEPT_HEADERS)
            headers["Accept-Language"] = random.choice(ACCEPT_LANGUAGES)
            headers["Accept-Encoding"] = "gzip, deflate, br"
            headers["Connection"] = "keep-alive"
            headers["Upgrade-Insecure-Requests"] = "1"
            # Randomize header order by using different sec- headers
            if random.random() > 0.5:
                headers["Sec-Fetch-Dest"] = "document"
                headers["Sec-Fetch-Mode"] = "navigate"
                headers["Sec-Fetch-Site"] = random.choice(["none", "same-origin"])

        return headers

    # ── Payload Stealth ───────────────────────

    def should_mutate_payload(self) -> bool:
        """Decide whether to mutate a payload based on stealth profile."""
        return random.random() < self._profile.payload_mutation_rate

    def get_scan_config(self) -> Dict[str, Any]:
        """Get scan configuration adjusted for current stealth profile."""
        return {
            "threads": self._profile.max_concurrent_requests,
            "rate_limit": self._profile.max_requests_per_second,
            "delay_ms": self._profile.request_delay_ms,
            "crawl_depth": self._profile.crawl_depth,
            "stealth_mode": self._profile.mode.value,
            "threat_level": self._profile.threat_level.value,
            "rotate_ua": self._profile.rotate_user_agents,
            "fingerprint_rotation": self._profile.fingerprint_rotation,
        }

    # ── Summary ───────────────────────────────

    def get_summary(self) -> Dict[str, Any]:
        return {
            "mode": self._profile.mode.value,
            "threat_level": self._profile.threat_level.value,
            "delay_ms": self._profile.request_delay_ms,
            "max_rps": self._profile.max_requests_per_second,
            "blocking_indicators": len(self._blocking_indicators),
            "escalation_count": self._escalation_count,
            "recent_blocks": len([i for i in self._blocking_indicators
                                  if time.time() - i.timestamp < 300]),
        }
