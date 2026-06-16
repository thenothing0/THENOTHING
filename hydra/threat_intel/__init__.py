"""
Hydra Threat Intelligence & Knowledge Fusion — Phase U.

The fusion layer. It transforms Hydra from "knowing capabilities" into "understanding evolving
threats, adversaries, campaigns, techniques, skills, opportunities, and knowledge signals together"
— by REASONING OVER Hydra's existing knowledge graph. It does NOT execute, does NOT attack, does NOT
collect live intelligence.

A **Threat** is keyed by an ATT&CK tactic and fuses all seven reused layers — Federation (N),
Temporal (O), Offensive (P), Campaign (Q), Skill (R), Opportunity (S), Adversary (T) — over ONE
shared ThreatContext (a single OffensiveContext load threaded through Phase-T → S/Q/R, plus bounded
guarded O and N signals). Builds a fully-explainable Threat→Campaign→Technique→Capability→Skill→Agent
graph (every edge carries a reason), deterministic clustering, temporal threat evolution, threat↔
opportunity / skill / campaign / adversary fusion, per-threat risk, and a versioned 0-100 threat
health. Store-free (no embedded datastore), deterministic, advisory-only, NON-executing;
promotion.py / confidence.py / the canonical wiki are untouched.
"""

from hydra.threat_intel.adversary_linking import AdversaryLinker
from hydra.threat_intel.advisor import ThreatAdvisor
from hydra.threat_intel.campaign_linking import CampaignLinker
from hydra.threat_intel.context import ThreatContext
from hydra.threat_intel.intelligence import ThreatIntelligence
from hydra.threat_intel.opportunity_linking import OpportunityLinker
from hydra.threat_intel.risk_scoring import ThreatRiskScorer
from hydra.threat_intel.skill_linking import SkillLinker
from hydra.threat_intel.threat_graph import ThreatGraph
from hydra.threat_intel.threat_model import Threat, ThreatModel
from hydra.threat_intel.trend_fusion import ThreatEvolution

__all__ = [
    "ThreatContext",
    "Threat",
    "ThreatModel",
    "ThreatGraph",
    "ThreatEvolution",
    "ThreatRiskScorer",
    "AdversaryLinker",
    "CampaignLinker",
    "SkillLinker",
    "OpportunityLinker",
    "ThreatAdvisor",
    "ThreatIntelligence",
]
