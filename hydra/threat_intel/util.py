"""
Deterministic threat-intelligence math (Phase U).

Re-exports the pure offensive math from Phase P (no duplication) plus the versioned threat-fusion
constants. NO randomness, NO wall-clock — the whole threat-intelligence layer is rebuild-identical.
Advisory only; NON-executing. This layer FUSES the existing knowledge layers (N/O/P/Q/R/S/T); it
never collects live intelligence.
"""

from __future__ import annotations

from hydra.offensive_intel.util import jaccard, mean, norm  # noqa: F401  (shared, re-exported)

# Versioned threat-scoring constants → explainable & stable. Bump only on an intentional change.
THREAT_SCORING_VERSION = 1

# Per-threat RISK weights (sum to 1.0 → risk in [0,1]; higher = more exposed / worse covered).
W_COVERAGE_DEFICIT = 0.45     # 1 - covered/in-scope techniques
W_OPPORTUNITY_GAP = 0.35      # mean Phase-S opportunity score of backing capabilities (unrealized)
W_DECAY = 0.20                # fraction of backing capabilities declining (Phase-O)

# threat_health blend (base weights sum to 1.0; federation is a small capped bonus on top).
H_COVERAGE = 0.30
H_RESILIENCE = 0.15           # non-fragile (multi-provider) technique fraction = "redundancy"
H_DIVERSITY = 0.20           # category diversity across covered threats
H_REALIZATION = 0.20         # 1 - mean opportunity gap
H_DECAY = 0.15               # 1 - mean temporal decay
FEDERATION_HEALTH_BONUS = 5.0  # capped additive bonus when peers corroborate (Phase-N)

# Clustering: two threats are "related" when their capability Jaccard ≥ this.
CLUSTER_JACCARD = 0.30


def clamp01(x: float) -> float:
    """Clamp a float into [0.0, 1.0] (deterministic, bounded)."""
    return 0.0 if x < 0.0 else (1.0 if x > 1.0 else x)
