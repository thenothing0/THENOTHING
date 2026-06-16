"""
SkillTechniqueMapper (Phase T) — which skills contribute to which ATT&CK techniques.

Maps each Phase-R skill, through its capabilities, onto the in-scope ATT&CK techniques (and their
tactics) it contributes to. Deterministic, read-only, advisory; O(S·C) bounded by the small skill
set. NON-executing — it describes the MODEL.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from hydra.adversary_intel.context import AdversaryContext


class SkillTechniqueMapper:
    def __init__(self, ac: Optional[AdversaryContext] = None):
        self.ac = ac or AdversaryContext()
        self._rows_cache: Optional[List[Dict]] = None

    def _rows(self) -> List[Dict]:
        if self._rows_cache is not None:
            return self._rows_cache
        mapping = self.ac.mapping()
        rows: List[Dict] = []
        for s in self.ac.skill().cc.skill_map():
            techs = sorted({tid for cap in s["capabilities"]
                            for tid in mapping.techniques_for_capability(cap)})
            tactics = sorted({mapping.technique(t).tactic_id for t in techs
                              if mapping.technique(t)})
            rows.append({
                "skill_id": s["skill_id"], "name": s["name"], "category": s["category"],
                "techniques": techs, "technique_count": len(techs),
                "tactics": tactics, "tactic_count": len(tactics),
                "skill_effectiveness": s["skill_effectiveness"], "advisory": True,
            })
        rows.sort(key=lambda r: (-r["technique_count"], r["skill_id"]))
        self._rows_cache = rows
        return rows

    def get(self, skill_id: str) -> Optional[Dict]:
        return next((r for r in self._rows() if r["skill_id"] == skill_id), None)

    def report(self) -> Dict:
        rows = self._rows()
        contributing = [r for r in rows if r["technique_count"] > 0]
        return {
            "skills": rows, "count": len(rows),
            "contributing_skills": len(contributing),
            "top": [r["skill_id"] for r in rows[:5]],
            "advisory": True,
        }
