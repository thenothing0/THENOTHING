"""
Deterministic campaign scoring helpers (Phase Q).

Re-exports the pure offensive math from Phase P (no duplication) plus campaign-specific versioned
constants. NO randomness, NO wall-clock — the whole campaign layer is rebuild-identical. Advisory only.
"""

from __future__ import annotations

from hydra.offensive_intel.util import jaccard, mean, norm  # noqa: F401  (shared, re-exported)

# Versioned campaign-scoring constants → explainable & stable. Bump only on an intentional change.
CAMPAIGN_SCORING_VERSION = 1
WEAK_EFFECTIVENESS = 0.40
DEPENDENCY_RISK_TOP = 10        # critical-capability depth used for dependency-risk scoring
