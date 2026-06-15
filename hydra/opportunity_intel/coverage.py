"""
CoverageSynthesizer (Phase S) — one unified coverage view fused across layers.

Synthesizes a single per-category coverage picture from FIVE dimensions:
  * effectiveness coverage   — Phase-P category mean effectiveness;
  * verification coverage    — Phase-P per-category verification-capable %;
  * exercise coverage        — Phase-P exercised %;
  * agent (workflow) coverage— Phase-P agent ownership %;
  * skill coverage           — Phase-R per-category capability-by-skill %.
Each dimension is normalized to [0,1]; a deterministic weighted blend yields a per-category
`coverage_index` and an overall coverage index. Read-only, advisory; O(C). Reuses the SHARED
OffensiveIntelligence (so no duplicate scans).
"""

from __future__ import annotations

from typing import Dict, List, Optional

from hydra.opportunity_intel.context import OpportunityContext
from hydra.opportunity_intel.util import mean

# Coverage-dimension weights (sum to 1.0 → coverage_index in [0,1]).
W_EFF = 0.30
W_VERIF = 0.20
W_EXERCISE = 0.20
W_AGENT = 0.15
W_SKILL = 0.15


class CoverageSynthesizer:
    def __init__(self, oc: Optional[OpportunityContext] = None):
        self.oc = oc or OpportunityContext()
        self._rows: Optional[List[Dict]] = None

    def _skill_cov_by_cat(self) -> Dict[str, float]:
        out: Dict[str, float] = {}
        for r in self.oc.skill().coverage.category_coverage():
            out[r["category"]] = r["coverage_pct"] / 100.0
        return out

    def synthesize(self) -> List[Dict]:
        if self._rows is not None:
            return self._rows
        owner = self.oc.owner_of()
        cat = self.oc.catalog()
        skill_cov = self._skill_cov_by_cat()
        rows: List[Dict] = []
        for c in self.oc.oi.coverage.category_coverage():
            category = c["category"]
            members = cat.by_category(category)
            n = len(members) or 1
            owned = sum(1 for m in members if owner.get(m.capability_id))
            eff = c["mean_effectiveness"]
            verif = c["verification_coverage_pct"] / 100.0
            exercise = c["exercised_pct"] / 100.0
            agent = owned / n
            skill = skill_cov.get(category, 0.0)
            index = (W_EFF * eff + W_VERIF * verif + W_EXERCISE * exercise
                     + W_AGENT * agent + W_SKILL * skill)
            rows.append({
                "category": category, "capabilities": c["capabilities"],
                "effectiveness": round(eff, 4),
                "verification_coverage": round(verif, 4),
                "exercise_coverage": round(exercise, 4),
                "agent_coverage": round(agent, 4),
                "skill_coverage": round(skill, 4),
                "coverage_index": round(index, 4), "advisory": True,
            })
        rows.sort(key=lambda d: (d["coverage_index"], d["category"]))
        self._rows = rows
        return rows

    def overall_index(self) -> float:
        rows = self.synthesize()
        return round(mean([r["coverage_index"] for r in rows]), 4) if rows else 0.0

    def report(self) -> Dict:
        rows = self.synthesize()
        return {
            "category_coverage": rows,
            "overall_coverage_index": self.overall_index(),
            "weakest_categories": rows[:5],
            "strongest_categories": list(reversed(rows[-5:])),
            "dimensions": ["effectiveness", "verification_coverage", "exercise_coverage",
                           "agent_coverage", "skill_coverage"],
            "advisory": True,
        }
