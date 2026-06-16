"""
ThreatIntelligence (Phase U) — the unified threat / knowledge-fusion read surface.

Composes the threat model / threat graph / clustering / evolution / risk scoring / the four linkers /
advisor over ONE shared ThreatContext and ONE shared ThreatModel (so the heavy synthesis runs once).
The ThreatContext reuses the Phase-P OffensiveIntelligence load-once threaded through Phase-T → S/Q/R,
plus bounded guarded Phase-O and Phase-N signals. Read-only, deterministic, advisory, NON-executing;
it FUSES existing knowledge and never collects live intelligence. promotion.py / confidence.py / the
canonical wiki are untouched.
"""

from __future__ import annotations

from typing import Dict, Optional

from hydra.threat_intel.adversary_linking import AdversaryLinker
from hydra.threat_intel.advisor import ThreatAdvisor
from hydra.threat_intel.campaign_linking import CampaignLinker
from hydra.threat_intel.context import ThreatContext
from hydra.threat_intel.opportunity_linking import OpportunityLinker
from hydra.threat_intel.risk_scoring import ThreatRiskScorer
from hydra.threat_intel.skill_linking import SkillLinker
from hydra.threat_intel.threat_graph import ThreatGraph
from hydra.threat_intel.threat_model import ThreatModel
from hydra.threat_intel.trend_fusion import ThreatEvolution
from hydra.threat_intel.util import THREAT_SCORING_VERSION


class ThreatIntelligence:
    def __init__(self, tc: Optional[ThreatContext] = None):
        self.tc = tc or ThreatContext()
        self.model = ThreatModel(self.tc)
        self.graph = ThreatGraph(self.tc, self.model)
        self.evolution = ThreatEvolution(self.tc, self.model)
        self.risk = ThreatRiskScorer(self.tc, self.model)
        self.adversary = AdversaryLinker(self.tc, self.model)
        self.campaign = CampaignLinker(self.tc, self.model)
        self.skills = SkillLinker(self.tc, self.model)
        self.opportunity = OpportunityLinker(self.tc, self.model)
        self.advisor = ThreatAdvisor(self.tc, self.model)

    # ── individual views ───────────────────────────────────────────────────────
    def threat_graph(self, threat_id: str = "", now: Optional[float] = None) -> Dict:
        out = self.graph.report(threat_id=threat_id)
        out["reference_time"] = self.tc.now(now)
        return out

    def threat_clusters(self, now: Optional[float] = None) -> Dict:
        clusters = self.model.clusters()
        return {"clusters": clusters, "count": len(clusters),
                "reference_time": self.tc.now(now), "advisory": True}

    def threat_evolution(self, now: Optional[float] = None) -> Dict:
        out = self.evolution.report()
        out["reference_time"] = self.tc.now(now)
        return out

    def threat_opportunities(self, now: Optional[float] = None) -> Dict:
        out = self.opportunity.report()
        out["reference_time"] = self.tc.now(now)
        return out

    def threat_skills(self, now: Optional[float] = None) -> Dict:
        out = self.skills.report()
        out["reference_time"] = self.tc.now(now)
        return out

    def threat_campaigns(self, now: Optional[float] = None) -> Dict:
        out = self.campaign.report()
        out["reference_time"] = self.tc.now(now)
        return out

    def threat_health(self, now: Optional[float] = None) -> Dict:
        return self.risk.threat_health(now)

    # ── summary ────────────────────────────────────────────────────────────────
    def threat_summary(self, now: Optional[float] = None) -> Dict:
        g = self.graph.build()
        risks = self.risk.ranked_risks()
        evo = self.evolution.report()
        clusters = self.model.clusters()
        adv = self.adversary.report()
        return {
            "threat_health": self.risk.threat_health(now),
            "threats": {"in_scope": len(self.model.in_scope()),
                        "model_only": [t.threat_id for t in self.model.threats() if t.model_only],
                        "highest_risk": risks["highest_risk"]},
            "graph": {"nodes": g["node_count"], "edges": g["edge_count"],
                      "node_counts": g["node_counts"]},
            "clusters": [{"cluster_id": c["cluster_id"], "threats": c["threats"]} for c in clusters],
            "evolution": {"rising": evo["rising"], "declining": evo["declining"],
                          "emerging_patterns": evo["emerging_patterns"]},
            "broadest_adversary_profiles": adv["broadest_profiles"],
            "recommendations": self.advisor.recommendations(limit=5),
            "scoring_version": THREAT_SCORING_VERSION,
            "total_events": self.tc.total_events(),
            "reference_time": self.tc.now(now), "advisory": True,
        }
