"""
OpportunityIntelligence (Phase S) — the unified opportunity read surface.

Composes the attack-surface model / coverage synthesizer / blind-spot analyzer / opportunity graph /
ranker / advisor over ONE shared OpportunityContext (which reuses the Phase-P OffensiveIntelligence
load-once and threads it into Phase-Q and Phase-R; Phase-O and Phase-N contribute bounded cross-store
signals). Read-only, deterministic, advisory, NON-executing; promotion.py / confidence.py / the
canonical wiki are untouched.
"""

from __future__ import annotations

from typing import Dict, Optional

from hydra.opportunity_intel.advisor import OpportunityAdvisor
from hydra.opportunity_intel.blindspots import BlindSpotAnalyzer
from hydra.opportunity_intel.context import OpportunityContext
from hydra.opportunity_intel.coverage import CoverageSynthesizer
from hydra.opportunity_intel.opportunity_graph import OpportunityGraph
from hydra.opportunity_intel.ranker import OpportunityRanker
from hydra.opportunity_intel.surface import AttackSurfaceModel
from hydra.opportunity_intel.util import OPPORTUNITY_SCORING_VERSION, clamp01, mean


class OpportunityIntelligence:
    def __init__(self, oc: Optional[OpportunityContext] = None):
        self.oc = oc or OpportunityContext()
        self.surface = AttackSurfaceModel(self.oc)
        self.coverage = CoverageSynthesizer(self.oc)
        self.blindspots = BlindSpotAnalyzer(self.oc)
        self.graph = OpportunityGraph(self.oc)
        self.ranker = OpportunityRanker(self.oc)
        self.advisor = OpportunityAdvisor(self.oc, self.ranker, self.coverage, self.blindspots)

    # ── individual views ───────────────────────────────────────────────────────
    def opportunity_surface(self, now: Optional[float] = None) -> Dict:
        out = self.surface.report()
        out["reference_time"] = self.oc.now(now)
        return out

    def opportunity_coverage(self, now: Optional[float] = None) -> Dict:
        out = self.coverage.report()
        out["reference_time"] = self.oc.now(now)
        return out

    def opportunity_blindspots(self, now: Optional[float] = None) -> Dict:
        out = self.blindspots.report()
        out["reference_time"] = self.oc.now(now)
        return out

    def opportunity_graph(self, now: Optional[float] = None) -> Dict:
        out = self.graph.report()
        out["reference_time"] = self.oc.now(now)
        return out

    def opportunity_ranking(self, capability_id: str = "", limit: int = 25,
                            now: Optional[float] = None) -> Dict:
        if capability_id:
            o = self.ranker.get(capability_id)
            out = o.to_dict() if o else {
                "opportunity_id": capability_id, "error": "unknown capability", "advisory": True}
        else:
            out = self.ranker.report(limit=limit)
        out["reference_time"] = self.oc.now(now)
        return out

    def opportunity_advisor(self, limit: int = 10, now: Optional[float] = None) -> Dict:
        return {"recommendations": self.advisor.recommendations(limit=limit),
                "safe_verbs": ["prioritize", "strengthen", "expand", "diversify",
                               "investigate", "improve"],
                "reference_time": self.oc.now(now), "advisory": True}

    # ── health & summary ────────────────────────────────────────────────────────
    def opportunity_health(self, now: Optional[float] = None) -> Dict:
        ref = self.oc.now(now)
        ranked = self.ranker.rank()
        total = len(ranked)
        if total == 0:
            return {"opportunity_health_score": None, "status": "no_opportunity_data",
                    "total_events": 0, "reference_time": ref, "advisory": True}
        coverage_index = self.coverage.overall_index()
        breadth = self.surface.report()["surface_breadth_index"]
        realization = round(1.0 - mean([o.coverage_deficit for o in ranked]), 4)
        bs = self.blindspots.report()
        total_caps = self.oc.catalog().count() or 1
        blind_health = round(1.0 - clamp01(bs["actionable_count"] / total_caps), 4)
        # Deterministic bounded blend: rewards realized broad coverage, penalizes blind spots.
        score = max(0.0, min(100.0, 100.0 * (
            0.35 * coverage_index + 0.20 * breadth
            + 0.25 * realization + 0.20 * blind_health)))
        return {
            "opportunity_health_score": round(score, 2),
            "status": "healthy" if score >= 60 else ("watch" if score >= 40 else "degrading"),
            "overall_coverage_index": coverage_index,
            "surface_breadth_index": breadth,
            "coverage_realization": realization,
            "blind_spot_health": blind_health,
            "actionable_blind_spots": bs["actionable_count"],
            "mean_opportunity_score": round(mean([o.score for o in ranked]), 4),
            "opportunities": total, "total_events": self.oc.total_events(),
            "data_mode": "learning" if self.oc.total_events() > 0 else "catalog_only",
            "reference_time": ref, "advisory": True,
        }

    def opportunity_summary(self, now: Optional[float] = None) -> Dict:
        surface = self.surface.report()
        cov = self.coverage.report()
        bs = self.blindspots.report()
        g = self.graph.report()
        return {
            "opportunity_health": self.opportunity_health(now),
            "surface": {"totals": surface["totals"],
                        "widest_categories": surface["widest_categories"],
                        "surface_breadth_index": surface["surface_breadth_index"]},
            "top_opportunities": [o.to_dict() for o in self.ranker.rank(limit=5)],
            "coverage": {"overall_coverage_index": cov["overall_coverage_index"],
                         "weakest_categories": cov["weakest_categories"]},
            "blind_spots": {"count": bs["count"], "actionable_count": bs["actionable_count"],
                            "by_type": bs["by_type"], "top_severity": bs["top_severity"][:5]},
            "graph": {"bottleneck_finding_types": g["bottleneck_count"],
                      "hub_capabilities": g["hub_capabilities"][:5]},
            "recommendations": self.advisor.recommendations(limit=5),
            "scoring_version": OPPORTUNITY_SCORING_VERSION,
            "total_events": self.oc.total_events(),
            "reference_time": self.oc.now(now), "advisory": True,
        }
