"""
Deterministic adversary-intelligence math (Phase T).

Re-exports the pure offensive math from Phase P (no duplication) plus the versioned ATT&CK-coverage
constants. NO randomness, NO wall-clock — the whole adversary-intelligence layer is rebuild-identical.
Advisory only; NON-executing.
"""

from __future__ import annotations

from hydra.offensive_intel.util import jaccard, mean, norm  # noqa: F401  (shared, re-exported)

# Versioned ATT&CK-coverage constants → explainable & stable. Bump only on an intentional change.
ADVERSARY_SCORING_VERSION = 1

# A technique counts as "covered" when its best supporting capability is at least this effective.
COVERED_EFFECTIVENESS = 0.40
WEAK_EFFECTIVENESS = 0.40

# Coverage status labels (deterministic).
COVERED = "covered"
WEAK = "weak"
UNCOVERED = "uncovered"
MODEL_ONLY = "model_only"

# Health blend weights (sum to 1.0 → score base in [0,1]).
W_TECHNIQUE = 0.40    # fraction of in-scope techniques that are covered
W_TACTIC = 0.30       # mean per-tactic technique coverage (over Hydra-covered tactics)
W_EFFECT = 0.30       # mean effectiveness of the covered techniques


def clamp01(x: float) -> float:
    """Clamp a float into [0.0, 1.0] (deterministic, bounded)."""
    return 0.0 if x < 0.0 else (1.0 if x > 1.0 else x)
