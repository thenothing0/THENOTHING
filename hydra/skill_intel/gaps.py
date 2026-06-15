"""
SkillGapAnalyzer (Phase R) — skill coverage gaps.

Capabilities with no skill, weak skills, and broken `chain_to` references (skill ids that don't
resolve). Read-only, advisory; O(S + C).
"""

from __future__ import annotations

from typing import Dict, List, Optional

from hydra.skill_intel.context import SkillContext
from hydra.skill_intel.util import WEAK_EFFECTIVENESS


class SkillGapAnalyzer:
    def __init__(self, cc: Optional[SkillContext] = None):
        self.cc = cc or SkillContext()

    def uncovered_capabilities(self) -> List[Dict]:
        cat = self.cc.catalog()
        c2s = self.cc.cap_to_skills()
        emap = self.cc.eff_map()
        rows = [{"capability_id": c.capability_id, "category": c.category,
                 "effectiveness": emap[c.capability_id].effectiveness
                 if c.capability_id in emap else None}
                for c in cat.all() if not c2s.get(c.capability_id)]
        rows.sort(key=lambda d: (d["category"], d["capability_id"]))
        return rows

    def weak_skills(self, threshold: float = WEAK_EFFECTIVENESS) -> List[Dict]:
        return [{"skill_id": s["skill_id"], "effectiveness": s["skill_effectiveness"]}
                for s in self.cc.skill_map()
                if s["skill_effectiveness"] is not None and s["skill_effectiveness"] < threshold]

    def broken_chain_to(self) -> List[Dict]:
        by_id = self.cc.skills_by_id()
        return [{"skill_id": s["skill_id"], "chain_to": ct}
                for s in self.cc.skill_map() for ct in s["chain_to"] if ct not in by_id]

    def report(self) -> Dict:
        unc = self.uncovered_capabilities()
        weak = self.weak_skills()
        return {"uncovered_capabilities": unc, "uncovered_count": len(unc),
                "weak_skills": weak, "weak_skill_count": len(weak),
                "broken_chain_to": self.broken_chain_to(), "advisory": True}
