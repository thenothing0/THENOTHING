"""
ThreatAdvisor (Phase U) — bounded advisory knowledge-fusion recommendations.

Translates the fused threat picture into a capped list of recommendations. Verbs are SAFE ONLY —
strengthen / expand / improve / prioritize / investigate / diversify — NEVER execute / attack /
emulate / collect / deploy. Deterministic, advisory, NON-executing.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from hydra.threat_intel.campaign_linking import CampaignLinker
from hydra.threat_intel.context import ThreatContext
from hydra.threat_intel.opportunity_linking import OpportunityLinker
from hydra.threat_intel.threat_model import ThreatModel
from hydra.threat_intel.trend_fusion import ThreatEvolution

SAFE_VERBS = ("strengthen", "expand", "improve", "prioritize", "investigate", "diversify")


class ThreatAdvisor:
    def __init__(self, tc: Optional[ThreatContext] = None, model: Optional[ThreatModel] = None):
        self.tc = tc or ThreatContext()
        self.model = model or ThreatModel(self.tc)
        self.opportunity = OpportunityLinker(self.tc, self.model)
        self.campaign = CampaignLinker(self.tc, self.model)
        self.evolution = ThreatEvolution(self.tc, self.model)

    def recommendations(self, limit: int = 10) -> List[Dict]:
        recs: List[Dict] = []

        # prioritize — opportunities that close the most risk
        for o in self.opportunity.report()["risk_closing_opportunities"][:3]:
            if o["risk_closed"] > 0:
                recs.append({"type": "prioritize", "target": o["capability_id"],
                             "rationale": f"closes risk across {o['threat_count']} threat(s)",
                             "suggested_action": f"prioritize improving capability '{o['capability_id']}'",
                             "confidence": round(min(1.0, o["risk_closed"]), 4), "advisory": True})

        # strengthen — highest-risk in-scope threats
        for t in self.model.in_scope():
            if t.risk_score is not None and t.risk_status in ("high", "moderate"):
                recs.append({"type": "strengthen", "target": t.threat_id,
                             "rationale": f"threat '{t.name}' risk {t.risk_score} ({t.risk_status})",
                             "suggested_action": f"strengthen coverage of threat {t.threat_id}",
                             "confidence": round(t.risk_score, 4), "advisory": True})

        # expand — weakest campaign paths
        camp = self.campaign.report()
        for r in camp["campaign_phases"][:2]:
            recs.append({"type": "expand", "target": r["phase"],
                         "rationale": f"campaign phase '{r['phase']}' mean coverage {r['mean_coverage']}",
                         "suggested_action": f"expand technique coverage for the '{r['phase']}' phase",
                         "confidence": round(1.0 - r["mean_coverage"], 4), "advisory": True})

        # diversify — fragile campaign stages
        for r in camp["fragile_stages"][:2]:
            recs.append({"type": "diversify", "target": r["phase"],
                         "rationale": f"{r['fragile_techniques']} fragile (single-provider) technique(s)",
                         "suggested_action": f"diversify capabilities behind the '{r['phase']}' phase",
                         "confidence": round(min(1.0, 0.2 * r["fragile_techniques"]), 4),
                         "advisory": True})

        # investigate — emerging threat patterns
        for tid in self.evolution.report()["emerging_patterns"][:2]:
            recs.append({"type": "investigate", "target": tid,
                         "rationale": "weakly-covered threat with emerging backing capabilities",
                         "suggested_action": f"investigate the emerging pattern around {tid}",
                         "confidence": 0.5, "advisory": True})

        recs.sort(key=lambda r: (-r["confidence"], r["type"], str(r["target"])))
        return recs[:max(1, limit)]
