"""
╔══════════════════════════════════════════════════════════════╗
║  Human Emulation Engine                                      ║
║  Realistic mouse movement, typing simulation, session        ║
║  pacing, navigation randomness, anti-bot evasion             ║
╚══════════════════════════════════════════════════════════════╝
"""

import asyncio
import logging
import math
import random
import time
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger("hydra.human_emulation")


@dataclass
class BrowsingProfile:
    """A realistic browsing behavior profile."""
    name: str = "default"
    avg_page_dwell_ms: int = 5000         # Time spent on page
    dwell_variance_ms: int = 3000
    avg_typing_speed_cpm: int = 250       # Characters per minute
    typing_variance: float = 0.3
    mouse_speed: float = 1.0              # Multiplier
    scroll_behavior: str = "natural"      # natural, quick, thorough
    click_accuracy: float = 0.95          # How accurately clicks land
    tab_switching_probability: float = 0.1
    back_button_probability: float = 0.05
    idle_probability: float = 0.03        # Random idle pauses
    max_idle_ms: int = 15000


# ── Pre-built Profiles ───────────────────────

PROFILES = {
    "casual": BrowsingProfile(
        name="casual",
        avg_page_dwell_ms=8000, dwell_variance_ms=5000,
        avg_typing_speed_cpm=180, typing_variance=0.4,
        mouse_speed=0.8, scroll_behavior="natural",
        idle_probability=0.08, max_idle_ms=30000,
    ),
    "researcher": BrowsingProfile(
        name="researcher",
        avg_page_dwell_ms=15000, dwell_variance_ms=8000,
        avg_typing_speed_cpm=300, typing_variance=0.2,
        mouse_speed=1.2, scroll_behavior="thorough",
        idle_probability=0.05, max_idle_ms=20000,
    ),
    "power_user": BrowsingProfile(
        name="power_user",
        avg_page_dwell_ms=3000, dwell_variance_ms=2000,
        avg_typing_speed_cpm=400, typing_variance=0.15,
        mouse_speed=1.5, scroll_behavior="quick",
        idle_probability=0.02, max_idle_ms=5000,
    ),
    "mobile": BrowsingProfile(
        name="mobile",
        avg_page_dwell_ms=6000, dwell_variance_ms=4000,
        avg_typing_speed_cpm=120, typing_variance=0.5,
        mouse_speed=0.6, scroll_behavior="natural",
        click_accuracy=0.85,
        idle_probability=0.1, max_idle_ms=45000,
    ),
}


class HumanEmulationEngine:
    """
    Realistic human behavior emulation engine.

    Capabilities:
      - Realistic mouse movement with Bézier curves
      - Typing simulation with variable speed and typos
      - Session pacing with natural dwell times
      - Navigation randomness (back, idle, tab switch)
      - Browser interaction modeling
      - Anti-bot evasion patterns
      - Believable interaction timing

    The Browser Agent MUST:
      - Emulate realistic users
      - Avoid automation fingerprints
      - Preserve believable workflows
    """

    def __init__(self, profile: str = "researcher"):
        self._profile = PROFILES.get(profile, PROFILES["researcher"])
        self._session_start = time.time()
        self._actions_log: List[Dict[str, Any]] = []
        self._page_count = 0

    @property
    def profile(self) -> BrowsingProfile:
        return self._profile

    def set_profile(self, profile_name: str):
        self._profile = PROFILES.get(profile_name, self._profile)

    # ── Mouse Movement ────────────────────────

    def generate_mouse_path(self, start: Tuple[int, int],
                             end: Tuple[int, int],
                             steps: int = 20) -> List[Tuple[int, int]]:
        """Generate a realistic mouse movement path using Bézier curves."""
        sx, sy = start
        ex, ey = end

        # Generate 2 random control points for cubic Bézier
        distance = math.sqrt((ex - sx) ** 2 + (ey - sy) ** 2)
        spread = distance * 0.3

        cp1 = (
            sx + random.gauss(0, spread) + (ex - sx) * 0.3,
            sy + random.gauss(0, spread) + (ey - sy) * 0.3,
        )
        cp2 = (
            sx + random.gauss(0, spread) + (ex - sx) * 0.7,
            sy + random.gauss(0, spread) + (ey - sy) * 0.7,
        )

        path = []
        for i in range(steps + 1):
            t = i / steps
            # Cubic Bézier
            x = ((1 - t) ** 3 * sx +
                 3 * (1 - t) ** 2 * t * cp1[0] +
                 3 * (1 - t) * t ** 2 * cp2[0] +
                 t ** 3 * ex)
            y = ((1 - t) ** 3 * sy +
                 3 * (1 - t) ** 2 * t * cp1[1] +
                 3 * (1 - t) * t ** 2 * cp2[1] +
                 t ** 3 * ey)

            # Add small random jitter
            x += random.gauss(0, 1)
            y += random.gauss(0, 1)

            path.append((int(x), int(y)))

        return path

    def generate_mouse_delays(self, path_length: int) -> List[float]:
        """Generate realistic delays between mouse movement steps."""
        delays = []
        base_delay = 0.01 / self._profile.mouse_speed

        for i in range(path_length):
            # Speed varies: slower at start/end, faster in middle
            t = i / max(path_length - 1, 1)
            speed_factor = 0.5 + 0.5 * math.sin(t * math.pi)
            delay = base_delay * (0.5 + speed_factor) + random.gauss(0, 0.003)
            delays.append(max(0.001, delay))

        return delays

    # ── Typing Simulation ─────────────────────

    def generate_typing_sequence(self, text: str) -> List[Tuple[str, float]]:
        """Generate a realistic typing sequence with delays."""
        sequence = []
        cpm = self._profile.avg_typing_speed_cpm
        base_delay = 60.0 / cpm  # seconds per character

        for i, char in enumerate(text):
            # Variable typing speed
            variance = self._profile.typing_variance
            delay = base_delay * random.gauss(1.0, variance)

            # Slower for special characters
            if char in "!@#$%^&*(){}[]|\\:;\"'<>,.?/~`":
                delay *= 1.5

            # Brief pause at word boundaries
            if char == " ":
                delay *= random.uniform(1.0, 2.0)

            # Occasional long pause (thinking)
            if random.random() < 0.02:
                delay += random.uniform(0.5, 2.0)

            # Occasional typo + backspace
            if random.random() < 0.03 and i < len(text) - 1:
                wrong_char = random.choice("abcdefghijklmnopqrstuvwxyz")
                sequence.append((wrong_char, delay))
                sequence.append(("BACKSPACE", random.uniform(0.05, 0.15)))
                delay = base_delay * 0.8  # Faster after correction

            sequence.append((char, max(0.02, delay)))

        return sequence

    # ── Page Interaction ──────────────────────

    async def simulate_page_dwell(self):
        """Simulate realistic time spent on a page."""
        dwell = self._profile.avg_page_dwell_ms + random.gauss(
            0, self._profile.dwell_variance_ms)
        dwell = max(1000, dwell)

        # Random idle pause
        if random.random() < self._profile.idle_probability:
            idle = random.randint(2000, self._profile.max_idle_ms)
            dwell += idle

        await asyncio.sleep(dwell / 1000.0)
        self._page_count += 1

    def generate_scroll_sequence(self, page_height: int,
                                  viewport_height: int = 800) -> List[Dict[str, Any]]:
        """Generate a realistic scroll sequence."""
        scrolls = []
        current_y = 0

        if self._profile.scroll_behavior == "quick":
            # Fast scrolling, big jumps
            while current_y < page_height:
                delta = random.randint(300, 800)
                current_y += delta
                scrolls.append({
                    "delta_y": delta,
                    "delay_ms": random.randint(100, 400),
                })
        elif self._profile.scroll_behavior == "thorough":
            # Slow, deliberate scrolling with pauses
            while current_y < page_height:
                delta = random.randint(100, 300)
                current_y += delta
                delay = random.randint(500, 2000)
                # Occasional pause to "read"
                if random.random() < 0.2:
                    delay += random.randint(1000, 5000)
                scrolls.append({"delta_y": delta, "delay_ms": delay})
        else:
            # Natural scrolling
            while current_y < page_height:
                delta = random.randint(150, 500)
                current_y += delta
                scrolls.append({
                    "delta_y": delta,
                    "delay_ms": random.randint(200, 800),
                })

        return scrolls

    # ── Navigation Patterns ───────────────────

    def should_go_back(self) -> bool:
        return random.random() < self._profile.back_button_probability

    def should_idle(self) -> bool:
        return random.random() < self._profile.idle_probability

    def get_idle_duration_ms(self) -> int:
        return random.randint(2000, self._profile.max_idle_ms)

    def randomize_link_order(self, links: List[str]) -> List[str]:
        """Randomize link visit order to appear more human."""
        shuffled = links.copy()
        # Don't fully randomize — humans tend to follow some order
        for i in range(len(shuffled)):
            if random.random() < 0.3:
                j = random.randint(0, len(shuffled) - 1)
                shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
        return shuffled

    # ── Anti-Bot Evasion ──────────────────────

    def get_browser_fingerprint_overrides(self) -> Dict[str, Any]:
        """Get browser fingerprint overrides to avoid detection."""
        return {
            "webdriver": False,
            "languages": [random.choice([
                ["en-US", "en"], ["en-GB", "en"],
                ["en-US", "en", "es"],
            ])],
            "platform": random.choice(["Win32", "MacIntel", "Linux x86_64"]),
            "hardwareConcurrency": random.choice([4, 8, 12, 16]),
            "deviceMemory": random.choice([4, 8, 16]),
            "maxTouchPoints": 0,
            "vendor": "Google Inc.",
            "renderer": random.choice([
                "ANGLE (NVIDIA GeForce GTX 1060)",
                "ANGLE (Intel HD Graphics 630)",
                "ANGLE (AMD Radeon RX 580)",
            ]),
        }

    def get_realistic_viewport(self) -> Tuple[int, int]:
        """Get a realistic viewport size."""
        viewports = [
            (1920, 1080), (1366, 768), (1536, 864),
            (1440, 900), (1280, 720), (2560, 1440),
            (1600, 900), (1680, 1050),
        ]
        return random.choice(viewports)

    # ── Logging ───────────────────────────────

    def log_action(self, action_type: str, details: Dict[str, Any] = None):
        self._actions_log.append({
            "action": action_type,
            "timestamp": time.time(),
            "details": details or {},
        })

    def get_summary(self) -> Dict[str, Any]:
        elapsed = time.time() - self._session_start
        return {
            "profile": self._profile.name,
            "session_duration": round(elapsed, 1),
            "pages_visited": self._page_count,
            "total_actions": len(self._actions_log),
        }
