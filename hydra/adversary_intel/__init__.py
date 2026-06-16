"""
Hydra Adversary & ATT&CK Intelligence — Phase T.

Derived, advisory, deterministic, offline-first analytics that model Hydra's offensive tradecraft
coverage against MITRE ATT&CK and the adversary profiles it supports. Built over a load-once
AdversaryContext that reuses the Phase-P OffensiveIntelligence (threaded through Phase-S
OpportunityIntelligence, which itself reuses Phase-Q CampaignIntelligence + Phase-R
SkillGraphIntelligence), plus a bounded Phase-O temporal signal.

A static, declarative AttackMapping ties ATT&CK tactics/techniques to Hydra's real capability
categories; coverage is scored from the Phase-P effectiveness engine. Out-of-scope / post-exploitation
tactics are MODEL-ONLY (Hydra provides no capability and no execution). Store-free (no embedded
datastore), NON-executing: it SCORES and ADVISES over the capability MODEL and never exploits,
emulates, validates, confirms, promotes, or executes. promotion.py / confidence.py / the canonical
wiki are untouched.
"""

from hydra.adversary_intel.advisor import AdversaryAdvisor
from hydra.adversary_intel.adversary_profiles import AdversaryProfileModeler
from hydra.adversary_intel.attack_mapping import AttackMapping, AttackTactic, AttackTechnique
from hydra.adversary_intel.capability_mapping import CapabilityTechniqueMapper
from hydra.adversary_intel.context import AdversaryContext
from hydra.adversary_intel.gap_analysis import AttackGapAnalyzer
from hydra.adversary_intel.intelligence import AdversaryIntelligence
from hydra.adversary_intel.skill_mapping import SkillTechniqueMapper
from hydra.adversary_intel.tactic_coverage import TacticCoverageAnalyzer
from hydra.adversary_intel.technique_coverage import TechniqueCoverage, TechniqueCoverageAnalyzer

__all__ = [
    "AdversaryContext",
    "AttackMapping",
    "AttackTactic",
    "AttackTechnique",
    "TechniqueCoverageAnalyzer",
    "TechniqueCoverage",
    "TacticCoverageAnalyzer",
    "AdversaryProfileModeler",
    "AttackGapAnalyzer",
    "SkillTechniqueMapper",
    "CapabilityTechniqueMapper",
    "AdversaryAdvisor",
    "AdversaryIntelligence",
]
