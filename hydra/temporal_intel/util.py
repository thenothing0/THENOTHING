"""
Deterministic temporal math (Phase O).

Pure, side-effect-free helpers shared by every temporal analyzer: fixed time-bucketing,
least-squares slope, mean/stdev, bounded linear extrapolation, and trend classification.
NO randomness, NO wall-clock — every function is a pure function of its inputs, so the whole
temporal layer is rebuild-identical given a fixed injected `now`.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence

# Fixed, versioned bucketing constants → deterministic boundaries across runs.
DEFAULT_BUCKET_SECONDS = 86_400.0      # 1 day
DEFAULT_WINDOW = 30                    # number of buckets analyzed (oldest..newest)
BUCKET_VERSION = 1                     # bump only on an intentional boundary change

# Classification / detection thresholds (fixed → explainable & stable).
TREND_EPS = 0.05                       # normalized-slope deadband for "stable"
ANOMALY_SIGMA = 2.5                    # spike/drop = > this many stdevs from mean
INACTIVITY_BUCKETS = 5                 # trailing empty buckets after activity = inactivity
CONCENTRATION_SHARE = 0.6              # one entity holding > this share = concentration


def mean(xs: Sequence[float]) -> float:
    return sum(xs) / len(xs) if xs else 0.0


def pstdev(xs: Sequence[float]) -> float:
    if len(xs) < 2:
        return 0.0
    mu = mean(xs)
    return (sum((x - mu) ** 2 for x in xs) / len(xs)) ** 0.5


def slope(ys: Sequence[float]) -> float:
    """Least-squares slope over evenly-spaced x = 0..n-1. Deterministic; 0.0 if n<2."""
    n = len(ys)
    if n < 2:
        return 0.0
    mx = (n - 1) / 2.0
    my = mean(ys)
    num = sum((x - mx) * (y - my) for x, y in enumerate(ys))
    den = sum((x - mx) ** 2 for x in range(n))
    return num / den if den else 0.0


def classify_trend(ys: Sequence[float]) -> str:
    """rising / declining / stable by slope normalized against the series magnitude."""
    s = slope(ys)
    norm = s / (mean(ys) + 1.0)
    if norm > TREND_EPS:
        return "rising"
    if norm < -TREND_EPS:
        return "declining"
    return "stable"


def momentum(ys: Sequence[float]) -> float:
    """Recent-half mean minus older-half mean (positive = building momentum)."""
    n = len(ys)
    if n < 2:
        return 0.0
    half = n // 2
    return round(mean(ys[half:]) - mean(ys[:half]), 6)


def acceleration(ys: Sequence[float]) -> float:
    """Change in slope between the older and recent halves (curvature sign)."""
    n = len(ys)
    if n < 4:
        return 0.0
    half = n // 2
    return round(slope(ys[half:]) - slope(ys[:half]), 6)


def forecast(ys: Sequence[float], horizon: int = 1,
             ma_window: int = 3) -> float:
    """Bounded linear extrapolation off a moving-average base (never stochastic).

    base = mean of the last `ma_window` buckets; projected = base + slope*horizon,
    clamped to [0, cap] where cap bounds runaway extrapolation."""
    if not ys:
        return 0.0
    base = mean(ys[-ma_window:]) if len(ys) >= ma_window else mean(ys)
    projected = base + slope(ys) * horizon
    cap = max(ys) * 3.0 + 1.0
    return round(min(max(projected, 0.0), cap), 4)


def bucket_index(ts: float, now: float, bucket_seconds: float, window: int) -> Optional[int]:
    """Map a timestamp to a bucket index (0 = oldest in-window, window-1 = most recent).
    Returns None for events outside the analyzed window or in the future-of-`now`."""
    age = now - ts
    if age < 0:
        age = 0.0
    b = int(age // bucket_seconds)
    if b >= window:
        return None
    return window - 1 - b


def bucket_counts(events, now: float, bucket_seconds: float = DEFAULT_BUCKET_SECONDS,
                  window: int = DEFAULT_WINDOW) -> Dict[str, List[float]]:
    """Per-entity weighted counts per bucket (oldest..newest). Single pass → O(E)."""
    out: Dict[str, List[float]] = {}
    for e in events:
        idx = bucket_index(e.occurred_at, now, bucket_seconds, window)
        if idx is None:
            continue
        series = out.get(e.entity)
        if series is None:
            series = [0.0] * window
            out[e.entity] = series
        series[idx] += e.weight
    return out


def bucket_success_rate(events, now: float, bucket_seconds: float = DEFAULT_BUCKET_SECONDS,
                        window: int = DEFAULT_WINDOW) -> Dict[str, List[float]]:
    """Per-entity success-rate per bucket (oldest..newest); buckets with no outcome → 0.0."""
    succ: Dict[str, List[float]] = {}
    tot: Dict[str, List[float]] = {}
    for e in events:
        if e.success is None:
            continue
        idx = bucket_index(e.occurred_at, now, bucket_seconds, window)
        if idx is None:
            continue
        if e.entity not in tot:
            succ[e.entity] = [0.0] * window
            tot[e.entity] = [0.0] * window
        tot[e.entity][idx] += 1.0
        if e.success:
            succ[e.entity][idx] += 1.0
    out: Dict[str, List[float]] = {}
    for ent, t in tot.items():
        out[ent] = [round(succ[ent][i] / t[i], 4) if t[i] else 0.0 for i in range(window)]
    return out
