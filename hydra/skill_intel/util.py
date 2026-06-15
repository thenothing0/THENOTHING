"""
Deterministic skill-intelligence math (Phase R).

Re-exports the pure offensive math from Phase P (no duplication) plus skill-specific versioned
constants. NO randomness, NO wall-clock — the whole skill-intelligence layer is rebuild-identical.
Advisory only.
"""

from __future__ import annotations

from hydra.offensive_intel.util import jaccard, mean, norm  # noqa: F401  (shared, re-exported)

# Versioned skill-scoring constants → explainable & stable. Bump only on an intentional change.
SKILL_SCORING_VERSION = 1
WEAK_EFFECTIVENESS = 0.40
