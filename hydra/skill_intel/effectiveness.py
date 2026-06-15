"""
SkillEffectivenessAnalyzer (Phase R) — per-skill effectiveness / utility / uniqueness / redundancy.

Effectiveness is taken from the Phase-P skill bridge; utility weights it by capability breadth;
uniqueness/redundancy come from capability-set overlap with peer skills. Deterministic, read-only,
advisory; O(S^2) bounded by #skills (a small constant).
"""

from __future__ import annotations

from typing import Dict, List, Optional

from hydra.skill_intel.context import SkillContext
from hydra.skill_intel.util import SKILL_SCORING_VERSION, jaccard, mean, norm


class SkillEffectivenessAnalyzer:
    def __init__(self, cc: Optional[SkillContext] = None):
        self.cc = cc or SkillContext()
        self._rows_cache: Optional[List[Dict]] = None

    def _rows(self) -> List[Dict]:
        if self._rows_cache is not None:
            return self._rows_cache
        sm = self.cc.skill_map()
        capsets = {s["skill_id"]: set(s["capabilities"]) for s in sm}
        max_caps = max((len(v) for v in capsets.values()), default=1) or 1
        rows = []
        for s in sm:
            sid = s["skill_id"]
            mine = capsets[sid]
            peers = [p for p in capsets if p != sid and capsets[p] & mine]
            red = mean([jaccard(mine, capsets[p]) for p in sorted(peers)]) if peers else 0.0
            eff = s["skill_effectiveness"]
            rows.append({
                "skill_id": sid, "name": s["name"], "category": s["category"],
                "effectiveness": eff, "capability_count": s["capability_count"],
                "utility": round((eff or 0.0) * norm(len(mine), max_caps), 4),
                "uniqueness": round(1.0 - red, 4), "redundancy": round(red, 4),
                "verification_capable_caps": s["verification_capable_caps"],
                "agents": s["agents"], "advisory": True})
        rows.sort(key=lambda r: (-(r["effectiveness"] or 0.0), r["skill_id"]))
        self._rows_cache = rows
        return rows

    def rank(self, limit: Optional[int] = None) -> List[Dict]:
        r = self._rows()
        return r[:limit] if limit else r

    def get(self, skill_id: str) -> Optional[Dict]:
        return next((r for r in self._rows() if r["skill_id"] == skill_id), None)

    def report(self) -> Dict:
        rows = self._rows()
        return {"skills": rows, "count": len(rows), "scoring_version": SKILL_SCORING_VERSION,
                "top": [r["skill_id"] for r in rows[:5]],
                "weakest": [r["skill_id"] for r in sorted(
                    rows, key=lambda r: ((r["effectiveness"] or 0.0), r["skill_id"]))[:5]],
                "advisory": True}
