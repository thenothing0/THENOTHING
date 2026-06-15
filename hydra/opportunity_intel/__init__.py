"""
Hydra Opportunity Intelligence — Phase S.

Derived, advisory, deterministic, offline-first analytics that identify WHERE Hydra's highest-value,
least-covered, most-leveraged offensive OPPORTUNITIES are. Built over a load-once OpportunityContext
that reuses the Phase-P OffensiveIntelligence (and threads that same instance into the Phase-Q
CampaignIntelligence and Phase-R SkillGraphIntelligence), with bounded cross-store signals from the
Phase-O temporal layer (emerging capabilities) and the Phase-N federation layer (peer demand).

Composes an attack-surface model, a fused coverage synthesizer, a blind-spot analyzer, an
opportunity graph, a versioned OpportunityScore ranker, and a safe-verb advisor. Store-free (no
embedded datastore), NON-executing: it SCORES and ADVISES over the capability MODEL and never
exploits, validates, confirms, promotes, or executes. promotion.py / confidence.py / the canonical
wiki are untouched.
"""

from hydra.opportunity_intel.advisor import OpportunityAdvisor
from hydra.opportunity_intel.blindspots import BlindSpotAnalyzer
from hydra.opportunity_intel.context import OpportunityContext
from hydra.opportunity_intel.coverage import CoverageSynthesizer
from hydra.opportunity_intel.intelligence import OpportunityIntelligence
from hydra.opportunity_intel.opportunity_graph import OpportunityGraph
from hydra.opportunity_intel.ranker import Opportunity, OpportunityRanker
from hydra.opportunity_intel.surface import AttackSurfaceModel

__all__ = [
    "OpportunityContext",
    "AttackSurfaceModel",
    "CoverageSynthesizer",
    "BlindSpotAnalyzer",
    "OpportunityGraph",
    "OpportunityRanker",
    "Opportunity",
    "OpportunityAdvisor",
    "OpportunityIntelligence",
]
