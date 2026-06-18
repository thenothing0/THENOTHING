"""
4-Tier Continuous Learning Store (architecture spec Part 2).

Tiers (narrow → broad): PROJECT (this engagement) → PERSONAL (this operator) →
CROSS (operator's projects) → ORG (team, opt-in). One SQLite store; each lesson
carries provenance (hashed target host — no target leakage across tiers), a trust
score, and a status. The WRITE PATH is a poison gate: target-derived steering /
exfil text (TN-1) is quarantined (stored for audit, never retrieved). RETRIEVAL
fences results as untrusted data (TN-2). Promotion to broader tiers is approval-
gated; org tier needs >=2 independent confirmations.

Distinct from `hydra/continuous_learning` (exploit-methodology intelligence): this
is the cross-engagement *lesson* KB PentesterFlow calls "continuous learning".
"""

from .store import (
    TIER_ORDER,
    LearningTiersStore,
    Lesson,
)

__all__ = ["LearningTiersStore", "Lesson", "TIER_ORDER"]
