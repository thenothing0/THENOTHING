"""
SkillCoverageAnalyzer (Phase R) — skill coverage of the capability surface.

Per-category skill coverage (skills, capabilities covered, mean effectiveness) and the overall
capability coverage (capabilities covered by >=1 skill vs uncovered). Read-only, advisory; O(S + C).
"""

from __future__ import annotations

from typing import Dict, List, Optional

from hydra.skill_intel.context import SkillContext
from hydra.skill_intel.util import mean


class SkillCoverageAnalyzer:
    def __init__(self, cc: Optional[SkillContext] = None):
        self.cc = cc or SkillContext()

    def category_coverage(self) -> List[Dict]:
        cat = self.cc.catalog()
        skills_by_cat: Dict[str, List[Dict]] = {}
        for s in self.cc.skill_map():
            skills_by_cat.setdefault(s["category"], []).append(s)
        rows = []
        for category in sorted({c.category for c in cat.all()}):
            members = skills_by_cat.get(category, [])
            effs = [s["skill_effectiveness"] for s in members if s["skill_effectiveness"] is not None]
            ncaps = len(cat.by_category(category))
            covered = {c for s in members for c in s["capabilities"]
                       if (e := cat.get(c)) and e.category == category}
            rows.append({"category": category, "skills": len(members), "capabilities": ncaps,
                         "capabilities_covered": len(covered),
                         "coverage_pct": round(100 * len(covered) / ncaps, 1) if ncaps else 0.0,
                         "mean_skill_effectiveness": round(mean(effs), 4) if effs else None})
        rows.sort(key=lambda d: (d["coverage_pct"], d["category"]))
        return rows

    def capability_coverage(self) -> Dict:
        cat = self.cc.catalog()
        c2s = self.cc.cap_to_skills()
        total = cat.count()
        covered = sum(1 for c in cat.all() if c2s.get(c.capability_id))
        return {"total_capabilities": total, "covered_by_skill": covered,
                "uncovered": total - covered,
                "coverage_pct": round(100 * covered / total, 1) if total else 0.0}

    def report(self) -> Dict:
        return {"category_coverage": self.category_coverage(),
                "capability_coverage": self.capability_coverage(), "advisory": True}
