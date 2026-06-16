"""Small shared helpers for the attack section. Deterministic; no I/O."""

from __future__ import annotations


def clamp01(x: float) -> float:
    return 0.0 if x < 0.0 else (1.0 if x > 1.0 else x)
