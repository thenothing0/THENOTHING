"""
Hydra Skill Composition & Skill Graph Intelligence — Phase R.

Promotes Skills into first-class architecture entities: a skill dependency graph (derived from the
capability dependency graph), a skill composition graph (shared capabilities), skill bundles,
per-skill effectiveness, skill coverage, skill gaps, an advisory skill marketplace, and bounded
recommendations. Store-free (a pure function of the static catalogs + the Phase-P offensive
intelligence). Read-only, deterministic, advisory, NON-executing.

This is a NEW package (`hydra.skill_intel`) — it does NOT modify the legacy `hydra.skills`
operational subsystem; it only reads skills (through the Phase-P skill bridge). Skills never execute,
never modify capability/promotion/confidence state, never create runtime actions, and never become a
canonical source.
"""

from hydra.skill_intel.advisor import SkillAdvisor
from hydra.skill_intel.bundles import SkillBundles
from hydra.skill_intel.composition import SkillComposition
from hydra.skill_intel.context import SkillContext
from hydra.skill_intel.coverage import SkillCoverageAnalyzer
from hydra.skill_intel.dependencies import SkillDependencyAnalyzer
from hydra.skill_intel.effectiveness import SkillEffectivenessAnalyzer
from hydra.skill_intel.gaps import SkillGapAnalyzer
from hydra.skill_intel.intelligence import SkillGraphIntelligence
from hydra.skill_intel.marketplace import SkillMarketplace
from hydra.skill_intel.skill_graph import SkillGraph

__all__ = [
    "SkillContext",
    "SkillGraph",
    "SkillDependencyAnalyzer",
    "SkillComposition",
    "SkillBundles",
    "SkillEffectivenessAnalyzer",
    "SkillCoverageAnalyzer",
    "SkillGapAnalyzer",
    "SkillMarketplace",
    "SkillAdvisor",
    "SkillGraphIntelligence",
]
