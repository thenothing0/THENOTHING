"""
Hydra Offensive Capability Intelligence — Phase P.

Derived, advisory, deterministic, offline-first analytics over the EFFECTIVENESS, COVERAGE,
composition, OVERLAP and ATTACK-PATH value of capabilities, workflows, agents, plugins and skills.
Built from the existing derived learning logs + the static declarative catalogs via a load-once
OffensiveContext (O(E)). NON-executing: it scores and advises only — it never exploits, validates,
confirms, promotes, or executes. promotion.py / confidence.py / the canonical wiki are untouched.
"""

from hydra.offensive_intel.advisor import OffensiveAdvisor
from hydra.offensive_intel.chains import AttackChainIntelligence
from hydra.offensive_intel.context import OffensiveContext
from hydra.offensive_intel.coverage import OffensiveCoverageAnalyzer
from hydra.offensive_intel.effectiveness import (
    CapabilityEffectiveness,
    CapabilityEffectivenessEngine,
)
from hydra.offensive_intel.gaps import OffensiveGapAnalyzer
from hydra.offensive_intel.intelligence import OffensiveIntelligence
from hydra.offensive_intel.overlap import OverlapAnalyzer
from hydra.offensive_intel.skills import SkillIntelligence

__all__ = [
    "OffensiveContext",
    "CapabilityEffectivenessEngine",
    "CapabilityEffectiveness",
    "OffensiveCoverageAnalyzer",
    "AttackChainIntelligence",
    "OverlapAnalyzer",
    "OffensiveGapAnalyzer",
    "SkillIntelligence",
    "OffensiveAdvisor",
    "OffensiveIntelligence",
]
