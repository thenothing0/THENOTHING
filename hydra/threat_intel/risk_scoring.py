"""
ThreatRiskScorer (Phase U) — per-threat risk ranking + the fused threat-health score.

Per-threat `risk_score` is computed in ThreatModel (coverage deficit + opportunity gap + temporal
decay; model-only tactics are `out_of_scope`, never a fixable risk). This module ranks those risks
and computes the versioned 0-100 `threat_health` from SIX explainable inputs:
coverage · redundancy/resilience · diversity · opportunity gaps · temporal decay · federation
consensus. Deterministic, read-only, advisory; O(threats).
"""

from __future__ import annotations

from typing import Dict, Optional

from hydra.threat_intel.context import ThreatContext
from hydra.threat_intel.threat_model import ThreatModel
from hydra.threat_intel.util import (
    FEDERATION_HEALTH_BONUS,
    H_COVERAGE,
    H_DECAY,
    H_DIVERSITY,
    H_REALIZATION,
    H_RESILIENCE,
    THREAT_SCORING_VERSION,
    clamp01,
    mean,
)


class ThreatRiskScorer:
    def __init__(self, tc: Optional[ThreatContext] = None, model: Optional[ThreatModel] = None):
        self.tc = tc or ThreatContext()
        self.model = model or ThreatModel(self.tc)

    def ranked_risks(self) -> Dict:
        scored = [t for t in self.model.in_scope() if t.risk_score is not None]
        scored.sort(key=lambda t: (-(t.risk_score or 0.0), t.threat_id))
        rows = [{"threat_id": t.threat_id, "name": t.name, "risk_score": t.risk_score,
                 "risk_status": t.risk_status, "coverage_ratio": t.coverage_ratio,
                 "opportunity_gap": t.opportunity_gap, "decay": t.decay,
                 "risk_components": t.components, "advisory": True} for t in scored]
        return {"risks": rows, "count": len(rows),
                "highest_risk": [r["threat_id"] for r in rows[:5]],
                "scoring_version": THREAT_SCORING_VERSION, "advisory": True}

    def threat_health(self, now: Optional[float] = None) -> Dict:
        ref = self.tc.now(now)
        in_scope = self.model.in_scope()
        if not in_scope:
            return {"threat_health_score": None, "status": "no_threat_data",
                    "total_events": 0, "reference_time": ref, "advisory": True}
        coverage = mean([t.coverage_ratio for t in in_scope])
        total_techs = sum(t.in_scope_techniques for t in in_scope)
        total_fragile = sum(t.fragile_techniques for t in in_scope)
        resilience = round(1.0 - (total_fragile / total_techs), 4) if total_techs else 0.0
        total_categories = len({c.category for c in self.tc.catalog().all()}) or 1
        covered_cats = {cat for t in in_scope for cat in t.categories}
        diversity = round(len(covered_cats) / total_categories, 4)
        opp_gap = mean([t.opportunity_gap for t in in_scope])
        decay = mean([t.decay for t in in_scope])
        fed = self.tc.federation_signal()["mean_confidence"]

        components = {
            "coverage": round(H_COVERAGE * coverage, 4),
            "resilience": round(H_RESILIENCE * resilience, 4),
            "diversity": round(H_DIVERSITY * diversity, 4),
            "realization": round(H_REALIZATION * (1.0 - opp_gap), 4),
            "low_decay": round(H_DECAY * (1.0 - decay), 4),
        }
        base = sum(components.values())
        fed_bonus = round(FEDERATION_HEALTH_BONUS * clamp01(fed), 4)
        score = max(0.0, min(100.0, 100.0 * base + fed_bonus))
        return {
            "threat_health_score": round(score, 2),
            "status": "healthy" if score >= 60 else ("watch" if score >= 40 else "degrading"),
            "coverage": round(coverage, 4), "resilience": resilience, "diversity": diversity,
            "mean_opportunity_gap": round(opp_gap, 4), "mean_decay": round(decay, 4),
            "federation_consensus": round(fed, 4), "federation_bonus": fed_bonus,
            "health_components": components,
            "in_scope_threats": len(in_scope),
            "model_only_threats": sum(1 for t in self.model.threats() if t.model_only),
            "scoring_version": THREAT_SCORING_VERSION,
            "total_events": self.tc.total_events(),
            "data_mode": "learning" if self.tc.total_events() > 0 else "catalog_only",
            "reference_time": ref, "advisory": True,
        }
