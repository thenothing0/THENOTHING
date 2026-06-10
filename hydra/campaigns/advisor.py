"""
CampaignAdvisor (Phase Q) — bounded advisory campaign recommendations.

Surfaces, at most `limit` deterministic recommendations: weak campaign phases, bottleneck
capabilities (single points of failure), weak skills. Verbs are strengthen / add-alternative —
NEVER exploit / run / validate / confirm / promote. Advisory, NON-executing; O(C + D).
"""

from __future__ import annotations

from typing import Dict, List, Optional

from hydra.campaigns.campaign_model import CampaignContext, CampaignModel
from hydra.campaigns.util import WEAK_EFFECTIVENESS, mean


class CampaignAdvisor:
    def __init__(self, cc: Optional[CampaignContext] = None):
        self.cc = cc or CampaignContext()
        self.model = CampaignModel(self.cc)

    def recommendations(self, limit: int = 10) -> List[Dict]:
        recs: List[Dict] = []
        emap = self.cc.eff_map()
        for p in self.model.phases():
            if p.advisory_model_only or not p.capabilities:
                continue
            effs = [emap[c].effectiveness for c in p.capabilities if c in emap]
            me = mean(effs) if effs else 0.0
            if me < WEAK_EFFECTIVENESS:
                recs.append({"type": "strengthen_phase", "target": p.phase,
                             "rationale": f"phase '{p.phase}' mean effectiveness {round(me, 4)}",
                             "suggested_action": f"add or exercise capabilities in {p.hydra_categories}",
                             "confidence": round(1.0 - me, 4), "advisory": True})
        for d in self.cc.graph().critical_capabilities(top=5):
            if d["dependents"] >= 2:
                recs.append({"type": "bottleneck", "target": d["capability_id"],
                             "rationale": f"{d['dependents']} capabilities depend on it (single point of failure)",
                             "suggested_action": f"add an alternative capability for '{d['capability_id']}'",
                             "confidence": round(min(1.0, d["dependents"] / 5.0), 4), "advisory": True})
        for s in self.cc.skill_map():
            se = s["skill_effectiveness"]
            if se is not None and se < WEAK_EFFECTIVENESS:
                recs.append({"type": "weak_skill", "target": s["skill_id"],
                             "rationale": f"skill '{s['skill_id']}' effectiveness {se}",
                             "suggested_action": "strengthen the capabilities behind this skill",
                             "confidence": round(1.0 - se, 4), "advisory": True})
        recs.sort(key=lambda r: (-r["confidence"], r["type"], str(r["target"])))
        return recs[:max(1, limit)]
