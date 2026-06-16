"""
AdversaryAdvisor (Phase T) — bounded advisory ATT&CK-coverage recommendations.

Translates coverage gaps into a capped list of recommendations. Verbs are SAFE ONLY — strengthen /
expand / improve / prioritize / investigate / diversify — NEVER execute / emulate / attack / deploy /
run a technique. Deterministic, advisory, NON-executing.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from hydra.adversary_intel.context import AdversaryContext
from hydra.adversary_intel.gap_analysis import AttackGapAnalyzer
from hydra.adversary_intel.util import clamp01

SAFE_VERBS = ("strengthen", "expand", "improve", "prioritize", "investigate", "diversify")


class AdversaryAdvisor:
    def __init__(self, ac: Optional[AdversaryContext] = None,
                 gaps: Optional[AttackGapAnalyzer] = None):
        self.ac = ac or AdversaryContext()
        self.gaps = gaps or AttackGapAnalyzer(self.ac)

    def recommendations(self, limit: int = 10) -> List[Dict]:
        recs: List[Dict] = []
        rep = self.gaps.report()
        emerging = self.ac.temporal_signal()["emerging"]

        # prioritize — opportunities that lift the most ATT&CK coverage
        for o in rep["opportunities_improving_coverage"][:3]:
            recs.append({"type": "prioritize", "target": o["capability_id"],
                         "rationale": f"strengthening it lifts {o['technique_count']} weak technique(s)",
                         "suggested_action": f"prioritize improving capability '{o['capability_id']}'",
                         "confidence": round(o["opportunity_score"], 4), "advisory": True})

        # strengthen — weakly-covered techniques
        for t in rep["weak_techniques"][:5]:
            recs.append({"type": "strengthen", "target": t["technique_id"],
                         "rationale": f"technique '{t['name']}' weakly covered (best {t['best_effectiveness']})",
                         "suggested_action": f"strengthen capabilities behind {t['technique_id']}",
                         "confidence": round(clamp01(1.0 - t["best_effectiveness"]), 4),
                         "advisory": True})

        # expand — weak tactics (broaden technique coverage)
        for t in rep["weak_tactics"][:3]:
            recs.append({"type": "expand", "target": t["tactic_id"],
                         "rationale": f"tactic '{t['name']}' coverage {t['coverage_pct']}%",
                         "suggested_action": f"expand technique coverage for {t['tactic_id']}",
                         "confidence": round(clamp01(1.0 - t["coverage_pct"] / 100.0), 4),
                         "advisory": True})

        # investigate — emerging capabilities that back in-scope techniques
        for cap in sorted(emerging):
            techs = self.ac.mapping().techniques_for_capability(cap)
            if techs:
                recs.append({"type": "investigate", "target": cap,
                             "rationale": f"emerging capability backing {len(techs)} technique(s)",
                             "suggested_action": f"investigate the emerging capability '{cap}'",
                             "confidence": 0.5, "advisory": True})
                if sum(1 for r in recs if r["type"] == "investigate") >= 3:
                    break

        recs.sort(key=lambda r: (-r["confidence"], r["type"], str(r["target"])))
        return recs[:max(1, limit)]
