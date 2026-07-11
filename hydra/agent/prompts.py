"""Static planning knowledge for the offline, rule-based planner.

No LLM, no network, no new dependencies — just the mapping tables the planner
uses to turn a natural-language objective into a sequence of REAL HYDRA command
strings. Every command name here exists in the CommandRegistry.
"""

from __future__ import annotations

import re

# Target extraction — domains, URLs, IPv4. Deliberately conservative.
_DOMAIN_RE = re.compile(
    r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,})\b", re.IGNORECASE
)
_URL_RE = re.compile(r"\bhttps?://[^\s]+", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Vulnerability-class keywords → the class token /scan expects.
VULN_CLASS_KEYWORDS: dict[str, str] = {
    "xss": "xss",
    "cross-site scripting": "xss",
    "sqli": "sqli",
    "sql injection": "sqli",
    "ssrf": "ssrf",
    "ssti": "ssti",
    "template injection": "ssti",
    "lfi": "lfi",
    "local file": "lfi",
    "open redirect": "open_redirect",
    "redirect": "open_redirect",
    "idor": "idor",
    "rce": "rce",
}

DEFAULT_SCAN_CLASSES = ("xss", "sqli")

# Intent keywords → which capability "steps" to include, in order.
# Steps are abstract; the planner renders each into a real command for the target.
INTENT_STEPS: dict[str, tuple[str, ...]] = {
    "assess": ("scope", "recon", "scan", "knowledge", "report"),
    "pentest": ("scope", "recon", "scan", "attack", "report"),
    "full": ("scope", "recon", "scan", "attack", "knowledge", "report"),
    "audit": ("scope", "recon", "scan", "report"),
    "recon": ("scope", "recon"),
    "reconnaissance": ("scope", "recon"),
    "enumerate": ("scope", "recon"),
    "scan": ("recon", "scan"),
    "vulnerability": ("recon", "scan"),
    "attack": ("scope", "recon", "attack"),
    "exploit": ("scope", "recon", "attack"),
    "research": ("knowledge",),
    "investigate": ("knowledge", "recon"),
    "report": ("report",),
    "status": ("status",),
}

# Fallback when no intent keyword matches but a target is present.
DEFAULT_STEPS: tuple[str, ...] = ("scope", "recon", "scan", "report")

# Per-step metadata: (priority, base confidence, parallel_safe).
STEP_META: dict[str, tuple[int, float, bool]] = {
    "scope": (10, 0.9, False),
    "recon": (8, 0.8, False),
    "scan": (6, 0.65, False),
    "attack": (4, 0.5, False),
    "knowledge": (7, 0.85, True),
    "report": (2, 0.9, False),
    "status": (9, 0.95, True),
}

STOP_CONDITIONS: tuple[str, ...] = (
    "all_tasks_terminal",
    "goal_confidence_below_floor",
    "max_consecutive_failures",
)


def extract_target(text: str) -> str:
    """Return the first URL / domain / IPv4 in ``text`` (or "")."""
    m = _URL_RE.search(text)
    if m:
        return m.group(0).rstrip(".,);")
    m = _IPV4_RE.search(text)
    if m:
        return m.group(0)
    m = _DOMAIN_RE.search(text)
    return m.group(1) if m else ""


def extract_vuln_classes(text: str) -> list[str]:
    """Return vuln-class tokens mentioned in ``text`` (order-preserving, unique)."""
    lowered = text.lower()
    found: list[str] = []
    for keyword, token in VULN_CLASS_KEYWORDS.items():
        if keyword in lowered and token not in found:
            found.append(token)
    return found


def detect_steps(text: str) -> tuple[str, ...]:
    """Choose the ordered capability steps for an objective."""
    lowered = text.lower()
    for keyword, steps in INTENT_STEPS.items():
        if keyword in lowered:
            return steps
    return DEFAULT_STEPS
