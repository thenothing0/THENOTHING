"""
SkillAdvisor (Phase R) — bounded advisory skill recommendations.

Combines the marketplace recommendations with compact "cover uncovered capabilities" hints, capped
at `limit`. Verbs are author / strengthen / cover — NEVER execute / run / register / promote.
Deterministic, advisory, NON-executing.
"""

from __future__ import annotations

from collections import Counter
from typing import Dict, List, Optional

from hydra.skill_intel.context import SkillContext
from hydra.skill_intel.gaps import SkillGapAnalyzer
from hydra.skill_intel.marketplace import SkillMarketplace


class SkillAdvisor:
    def __init__(self, cc: Optional[SkillContext] = None):
        self.cc = cc or SkillContext()
        self.gaps = SkillGapAnalyzer(self.cc)
        self.market = SkillMarketplace(self.cc)

    def recommendations(self, limit: int = 10) -> List[Dict]:
        recs: List[Dict] = list(self.market.recommendations(limit=limit))
        counts = Counter(c["category"] for c in self.gaps.uncovered_capabilities())
        for category, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:3]:
            recs.append({"type": "cover_capabilities", "target": category,
                         "rationale": f"{n} capabilities in '{category}' have no skill",
                         "suggested_action": f"author a skill for the uncovered '{category}' capabilities",
                         "confidence": round(min(1.0, n / 10.0), 4), "advisory": True})
        recs.sort(key=lambda r: (-r["confidence"], r["type"], str(r["target"])))
        return recs[:max(1, limit)]
