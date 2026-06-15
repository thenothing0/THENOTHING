"""
Deterministic opportunity-intelligence math (Phase S).

Re-exports the pure offensive math from Phase P (no duplication) plus the versioned
opportunity-scoring constants. NO randomness, NO wall-clock — the whole opportunity-intelligence
layer is rebuild-identical. Advisory only.

The OpportunityScore is a NON-canonical MODEL ranking signal (it ranks Hydra's own capability
MODEL by where the highest-value, least-covered offensive opportunities are). It is deliberately
distinct from the Phase-D `OpportunityScore` (hydra/knowledge/opportunity.py), which ranks
discovery CANDIDATES (findings) — different domain, complementary, no overlap. Neither touches
promotion.py / confidence.py / the canonical wiki.
"""

from __future__ import annotations

from hydra.offensive_intel.util import jaccard, mean, norm  # noqa: F401  (shared, re-exported)

# Versioned opportunity-scoring constants → explainable & stable. Bump only on an intentional change.
OPPORTUNITY_SCORING_VERSION = 1

# OpportunityScore component weights (the five primary terms sum to 1.0 → score base in [0,1]).
W_VALUE = 0.35        # capability value (effectiveness × breadth = utility)
W_DEFICIT = 0.30      # coverage deficit (how under-covered the capability currently is)
W_CHAIN = 0.15        # chain potential (dependency centrality / contribution)
W_UNIQUE = 0.10       # uniqueness (1 - redundancy)
W_NOVELTY = 0.10      # novelty (never-exercised prior-only capability)

# Bounded additive bonuses from the cross-layer signals (capped so they never dominate).
TEMPORAL_BONUS_CAP = 0.05     # Phase-O: an "emerging" capability is a timely opportunity
FEDERATION_BONUS_CAP = 0.05   # Phase-N: federation demand (popular across peers)
FEDERATION_PER_PEER = 0.01    # demand bonus accrues 0.01 per adopting peer (capped)

# Advisory thresholds (fixed → deterministic, explainable).
WEAK_EFFECTIVENESS = 0.40
HIGH_OPPORTUNITY = 0.60       # a "strong" opportunity (prioritize)
HIGH_DEFICIT = 0.50           # a materially under-covered capability


def clamp01(x: float) -> float:
    """Clamp a float into [0.0, 1.0] (deterministic, bounded)."""
    return 0.0 if x < 0.0 else (1.0 if x > 1.0 else x)
