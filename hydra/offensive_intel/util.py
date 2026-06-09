"""
Deterministic offensive math (Phase P).

Pure, side-effect-free helpers shared by every offensive analyzer: evidence-damped blending of
observed signals toward a static prior, Jaccard overlap, normalization. NO randomness, NO
wall-clock — every function is a pure function of its inputs, so the whole offensive layer is
rebuild-identical. Advisory only.
"""

from __future__ import annotations

from typing import Iterable, List, Optional, Sequence

# Versioned scoring constants → explainable & stable. Bump only on an intentional change.
SCORING_VERSION = 1

# Effectiveness blend weights for the observed signals (the static prior damps cold-start).
W_SUCCESS = 0.5
W_VERIFICATION = 0.5
# Number of decided samples at which the observed signal fully overrides the prior.
SAMPLE_FULL = 10.0

# Advisory thresholds (fixed → deterministic, explainable).
WEAK_EFFECTIVENESS = 0.40
REDUNDANCY_THRESHOLD = 0.50
LOW_DIVERSITY = 0.40


def mean(xs: Sequence[float]) -> float:
    return sum(xs) / len(xs) if xs else 0.0


def jaccard(a: Iterable[str], b: Iterable[str]) -> float:
    """Set-overlap of two token collections; 0.0 when both are empty."""
    sa, sb = set(a), set(b)
    union = sa | sb
    return round(len(sa & sb) / len(union), 4) if union else 0.0


def blend_observed(success_rate: Optional[float],
                   verification_rate: Optional[float]) -> Optional[float]:
    """Weighted mean of the available observed rates; None when no signal is present."""
    parts: List[tuple] = []
    if success_rate is not None:
        parts.append((W_SUCCESS, success_rate))
    if verification_rate is not None:
        parts.append((W_VERIFICATION, verification_rate))
    if not parts:
        return None
    return sum(w * v for w, v in parts) / sum(w for w, _ in parts)


def damp_to_prior(prior: float, observed: Optional[float], samples: int) -> float:
    """Evidence-damped blend: samples 0 → prior; samples ≥ SAMPLE_FULL → observed.

    Deterministic and bounded; keeps cold-start scores anchored to the catalog prior and lets
    evidence move them smoothly as the learning logs fill."""
    if observed is None or samples <= 0:
        return round(prior, 4)
    d = min(1.0, samples / SAMPLE_FULL)
    return round(prior * (1.0 - d) + observed * d, 4)


def norm(value: float, maximum: float) -> float:
    return round(value / maximum, 4) if maximum > 0 else 0.0
