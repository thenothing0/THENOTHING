"""
OffensiveAdvisor (Phase P) — bounded advisory recommendations (no actions).

Emits at most `limit` deterministic recommendations: strengthen a weak category, reduce a redundant
pair, diversify a low-diversity chain, exercise an underutilized capability. Verbs are
strengthen / reduce / diversify / exercise — NEVER exploit / run / validate / confirm / promote.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from hydra.offensive_intel.chains import AttackChainIntelligence
from hydra.offensive_intel.context import OffensiveContext
from hydra.offensive_intel.coverage import OffensiveCoverageAnalyzer
from hydra.offensive_intel.effectiveness import CapabilityEffectivenessEngine
from hydra.offensive_intel.overlap import OverlapAnalyzer
from hydra.offensive_intel.util import LOW_DIVERSITY, WEAK_EFFECTIVENESS


class OffensiveAdvisor:
    def __init__(self, ctx: Optional[OffensiveContext] = None,
                 engine: Optional[CapabilityEffectivenessEngine] = None):
        self.ctx = (ctx or OffensiveContext()).load()
        self.engine = engine or CapabilityEffectivenessEngine(self.ctx)

    def recommendations(self, limit: int = 10) -> List[Dict]:
        recs: List[Dict] = []
        for c in OffensiveCoverageAnalyzer(self.ctx, self.engine).category_coverage():
            if c["mean_effectiveness"] < WEAK_EFFECTIVENESS or c["verification_coverage_pct"] == 0.0:
                recs.append({
                    "type": "strengthen_category", "target": c["category"],
                    "rationale": (f"category '{c['category']}' mean effectiveness "
                                  f"{c['mean_effectiveness']}, verification "
                                  f"{c['verification_coverage_pct']}%"),
                    "suggested_action": f"add or exercise capabilities in '{c['category']}'",
                    "confidence": round(1.0 - c["mean_effectiveness"], 4), "advisory": True})
        for p in OverlapAnalyzer(self.ctx, self.engine).redundant_pairs(threshold=0.6, limit=10):
            recs.append({
                "type": "reduce_redundancy", "target": [p["capability_a"], p["capability_b"]],
                "rationale": f"capabilities overlap {p['overlap']}",
                "suggested_action": f"review keeping the lower-value capability '{p['lower_value']}'",
                "confidence": p["overlap"], "advisory": True})
        for c in AttackChainIntelligence(self.ctx, self.engine).chains(limit=20)["chains"]:
            if c["diversity"] < LOW_DIVERSITY:
                recs.append({
                    "type": "diversify_workflow", "target": c["chain"],
                    "rationale": f"chain diversity {c['diversity']} (narrow category spread)",
                    "suggested_action": "introduce cross-category capabilities into this path",
                    "confidence": round(1.0 - c["diversity"], 4), "advisory": True})
        for e in self.engine.underutilized(5):
            recs.append({
                "type": "exercise_capability", "target": e.capability_id,
                "rationale": f"high prior ({e.effectiveness}) but only {e.samples} samples",
                "suggested_action": f"exercise '{e.capability_id}' to validate its prior",
                "confidence": e.effectiveness, "advisory": True})
        recs.sort(key=lambda r: (-r["confidence"], r["type"], str(r["target"])))
        return recs[:max(1, limit)]
