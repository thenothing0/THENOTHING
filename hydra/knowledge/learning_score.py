"""
learning_score — a transparent, deterministic 1–10 valuation of how much
*reusable attacker knowledge* a disclosed report carries.

This is the Phase-B scoring authority. It is intentionally **pure, explainable
and LLM-free**: the score is a function of structured signals the ingestion
pipeline already extracted (the vulnerability class, whether the report shows a
chain / privilege escalation / an uncommon pivot, and whether it looks like a
duplicate or trivial finding). Every score ships with a human-readable rationale
that lists the exact signals that moved it, so a researcher can audit *why* a
report ranks where it does.

No network, no hidden state — `score_report` is referentially transparent: the
same signals always yield the same `(score, rationale)`.
"""

from __future__ import annotations

from typing import List, Tuple

# ── Vulnerability-class base bands ────────────────────────────────────────────
# High band: classes that teach durable, creative, high-impact attacker tradecraft.
# Low band: classes that are usually low-signal (dupes / trivial / public-by-design).
# Everything else sits in the middle band. Keys are normalized vuln-class tokens
# (see _normalize) so both "auth_bypass" and "authz-bypass" land in the high band.
_HIGH_BAND = {
    "authz_bypass", "auth_bypass", "idor", "ssrf", "rce", "ssti",
    "deserialization", "xxe", "business_logic", "chain", "race_condition",
}
_LOW_BAND = {
    "misconfig", "info_disclosure", "information_disclosure", "public_key",
    "open_redirect", "unknown", "",
}

_HIGH_BASE = 6
_MID_BASE = 4
_LOW_BASE = 2

# Bonus / penalty signals. The pipeline detects these and records them on the
# ExtractedReport; the scorer only reads them (keeps scoring auditable).
BONUS_SIGNALS = {
    "chain": 2,        # the report stitches multiple bugs into one exploit path
    "escalation": 1,   # privilege / impact escalation demonstrated
    "pivot": 1,        # uncommon pivot / non-obvious technique
}
PENALTY_SIGNALS = {
    "duplicate": -3,   # explicitly a dupe / already-known
    "trivial": -2,     # low-effort, low-value finding
}

_MIN_SCORE = 1
_MAX_SCORE = 10


def _normalize(vuln_class: str) -> str:
    return str(vuln_class or "").strip().lower().replace("-", "_").replace(" ", "_")


def _band_base(vuln_class: str) -> Tuple[int, str]:
    norm = _normalize(vuln_class)
    if norm in _HIGH_BAND:
        return _HIGH_BASE, f"base {_HIGH_BASE} (high-value class '{norm}')"
    if norm in _LOW_BAND:
        return _LOW_BASE, f"base {_LOW_BASE} (low-signal class '{norm or 'unknown'}')"
    return _MID_BASE, f"base {_MID_BASE} (mid class '{norm}')"


def score_report(extracted) -> Tuple[int, str]:
    """Score an ExtractedReport's learning value in 1–10 with a rationale.

    Reads only structured attributes (duck-typed, so it never imports the
    pipeline and stays cycle-free and unit-testable in isolation):
      * ``extracted.vuln_class.value`` — the normalized vulnerability class
      * ``extracted.signals`` — a set/iterable of detected bonus/penalty tokens

    Returns ``(score, rationale)`` where score is clamped to [1, 10] and the
    rationale is a human-readable, ``" · "``-joined list of contributing signals.
    """
    vuln_class = _field_value(extracted, "vuln_class")
    signals = set(getattr(extracted, "signals", None) or [])

    base, base_reason = _band_base(vuln_class)
    score = base
    parts: List[str] = [base_reason]

    for sig, delta in BONUS_SIGNALS.items():
        if sig in signals:
            score += delta
            parts.append(f"+{delta} {sig}")
    for sig, delta in PENALTY_SIGNALS.items():
        if sig in signals:
            score += delta
            parts.append(f"{delta} {sig}")

    clamped = max(_MIN_SCORE, min(_MAX_SCORE, score))
    if clamped != score:
        parts.append(f"clamped {score}→{clamped}")

    return clamped, " · ".join(parts)


def _field_value(extracted, name: str):
    """Read a field that may be a plain value or an ExtractedField (has .value)."""
    field = getattr(extracted, name, None)
    return getattr(field, "value", field)
