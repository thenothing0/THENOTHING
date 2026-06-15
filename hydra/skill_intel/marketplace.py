"""
SkillMarketplace (Phase R) — advisory skill marketplace.

Surfaces where the skill ecosystem could grow: categories with low skill coverage, weak skills to
strengthen, and the overall capability coverage. Advisory only (it recommends authoring/strengthening
skills; it never creates, executes, or registers them). Read-only, deterministic; O(S + C).
"""

from __future__ import annotations

from typing import Dict, List, Optional

from hydra.skill_intel.context import SkillContext
from hydra.skill_intel.coverage import SkillCoverageAnalyzer
from hydra.skill_intel.gaps import SkillGapAnalyzer


class SkillMarketplace:
    def __init__(self, cc: Optional[SkillContext] = None):
        self.cc = cc or SkillContext()
        self.coverage = SkillCoverageAnalyzer(self.cc)
        self.gaps = SkillGapAnalyzer(self.cc)

    def recommendations(self, limit: int = 10) -> List[Dict]:
        recs: List[Dict] = []
        for c in self.coverage.category_coverage():
            if c["coverage_pct"] < 50.0:
                recs.append({"type": "add_skills_for_category", "target": c["category"],
                             "rationale": f"category '{c['category']}' skill coverage {c['coverage_pct']}%",
                             "suggested_action": f"author skills covering '{c['category']}' capabilities",
                             "confidence": round(1.0 - c["coverage_pct"] / 100.0, 4), "advisory": True})
        for w in self.gaps.weak_skills():
            recs.append({"type": "strengthen_skill", "target": w["skill_id"],
                         "rationale": f"skill effectiveness {w['effectiveness']}",
                         "suggested_action": "strengthen the capabilities behind this skill",
                         "confidence": round(1.0 - (w["effectiveness"] or 0.0), 4), "advisory": True})
        recs.sort(key=lambda r: (-r["confidence"], r["type"], str(r["target"])))
        return recs[:max(1, limit)]

    def report(self) -> Dict:
        recs = self.recommendations()
        return {"recommendations": recs, "opportunity_count": len(recs),
                "capability_coverage": self.coverage.capability_coverage(), "advisory": True}
