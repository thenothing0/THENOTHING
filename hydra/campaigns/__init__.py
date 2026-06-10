"""
Hydra Offensive Campaign Reasoning Engine — Phase Q.

Lifts Hydra from capability intelligence (Phase P) to CAMPAIGN-LEVEL reasoning: attack objectives,
campaign phases, capability sequencing, skill composition, attack-path generation, gaps, and
alternative strategies. Store-free (a pure function of the static catalogs + the Phase-P offensive
intelligence + declarative templates). Skills are first-class planning entities; a campaign is
explainable as BOTH a Capability Graph and a Skill Graph.

NON-executing: it reasons about campaign STRUCTURE only — it never executes, touches targets,
launches tools, confirms findings, or modifies promotion/confidence. Post-exploitation tactics are
MODEL-ONLY (`hydra_capability_coverage="none"`, `advisory_model_only=True`). The canonical wiki and
promotion.py / confidence.py are untouched.
"""

from hydra.campaigns.advisor import CampaignAdvisor
from hydra.campaigns.campaign_model import (
    CampaignContext,
    CampaignModel,
    CampaignPhase,
)
from hydra.campaigns.intelligence import CampaignIntelligence
from hydra.campaigns.objective_mapping import ObjectiveMapping
from hydra.campaigns.path_generation import PathGeneration
from hydra.campaigns.playbooks import PlaybookGenerator
from hydra.campaigns.simulation import CampaignSimulator
from hydra.campaigns.skill_bridge import CampaignSkillBridge
from hydra.campaigns.strategy import StrategyComparator
from hydra.campaigns.workflow_graph import WorkflowGraph

__all__ = [
    "CampaignContext",
    "CampaignModel",
    "CampaignPhase",
    "CampaignSkillBridge",
    "WorkflowGraph",
    "ObjectiveMapping",
    "PlaybookGenerator",
    "PathGeneration",
    "StrategyComparator",
    "CampaignSimulator",
    "CampaignAdvisor",
    "CampaignIntelligence",
]
