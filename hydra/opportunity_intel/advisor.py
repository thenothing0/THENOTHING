"""
OpportunityAdvisor (Phase S) — bounded advisory opportunity recommendations.

Translates the ranked opportunities, synthesized coverage, and blind spots into a capped list of
recommendations. Verbs are SAFE ONLY — prioritize / strengthen / expand / diversify / investigate /
improve — NEVER execute / exploit / attack / deploy / run. Deterministic, advisory, NON-executing.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from hydra.opportunity_intel.blindspots import BlindSpotAnalyzer
from hydra.opportunity_intel.context import OpportunityContext
from hydra.opportunity_intel.coverage import CoverageSynthesizer
from hydra.opportunity_intel.ranker import OpportunityRanker
from hydra.opportunity_intel.util import HIGH_OPPORTUNITY

SAFE_VERBS = ("prioritize", "strengthen", "expand", "diversify", "investigate", "improve")


class OpportunityAdvisor:
    def __init__(self, oc: Optional[OpportunityContext] = None,
                 ranker: Optional[OpportunityRanker] = None,
                 coverage: Optional[CoverageSynthesizer] = None,
                 blindspots: Optional[BlindSpotAnalyzer] = None):
        self.oc = oc or OpportunityContext()
        self.ranker = ranker or OpportunityRanker(self.oc)
        self.coverage = coverage or CoverageSynthesizer(self.oc)
        self.blindspots = blindspots or BlindSpotAnalyzer(self.oc)

    def recommendations(self, limit: int = 10) -> List[Dict]:
        recs: List[Dict] = []

        # prioritize — the strongest opportunities
        for o in self.ranker.rank(limit=5):
            if o.score >= HIGH_OPPORTUNITY:
                recs.append({"type": "prioritize", "target": o.opportunity_id,
                             "rationale": f"high opportunity score {o.score} ({o.category})",
                             "suggested_action": f"prioritize strengthening capability '{o.opportunity_id}'",
                             "confidence": round(o.score, 4), "advisory": True})

        # strengthen — weakest synthesized-coverage categories
        for c in self.coverage.synthesize()[:3]:
            recs.append({"type": "strengthen", "target": c["category"],
                         "rationale": f"low coverage_index {c['coverage_index']} for '{c['category']}'",
                         "suggested_action": f"strengthen coverage of the '{c['category']}' category",
                         "confidence": round(1.0 - c["coverage_index"], 4), "advisory": True})

        # expand — verification-blind categories (cannot validate)
        rep = self.blindspots.report()
        for s in rep["top_severity"]:
            if s["type"] == "verification_blind_category":
                recs.append({"type": "expand", "target": s["target"],
                             "rationale": s["rationale"],
                             "suggested_action": f"expand verification capability in '{s['target']}'",
                             "confidence": round(s["severity"], 4), "advisory": True})

        # diversify — redundant capability pairs (interchangeable capabilities)
        for pair in self.oc.oi.overlap.redundant_pairs(limit=3):
            recs.append({"type": "diversify",
                         "target": f"{pair['capability_a']}+{pair['capability_b']}",
                         "rationale": f"interchangeable capabilities (overlap {pair['overlap']})",
                         "suggested_action": "diversify or consolidate the redundant capabilities",
                         "confidence": round(float(pair.get("overlap", 0.0)), 4), "advisory": True})

        # investigate — novel, never-exercised high-value opportunities
        for o in self.ranker.rank():
            if o.status == "prior_only" and o.value > 0.0:
                recs.append({"type": "investigate", "target": o.opportunity_id,
                             "rationale": f"high-value never-exercised capability (value {o.value})",
                             "suggested_action": f"investigate exercising '{o.opportunity_id}'",
                             "confidence": round(o.value, 4), "advisory": True})
                if sum(1 for r in recs if r["type"] == "investigate") >= 3:
                    break

        recs.sort(key=lambda r: (-r["confidence"], r["type"], str(r["target"])))
        return recs[:max(1, limit)]
