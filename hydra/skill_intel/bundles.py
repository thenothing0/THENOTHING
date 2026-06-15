"""
SkillBundles (Phase R) — coherent skill bundles.

Bundles group skills by category (a natural, deterministic bundling), each carrying the union of
its skills' capabilities and agents plus a mean effectiveness. Read-only, advisory; O(S + C).
"""

from __future__ import annotations

from typing import Dict, List, Optional

from hydra.skill_intel.context import SkillContext
from hydra.skill_intel.util import mean


class SkillBundles:
    def __init__(self, cc: Optional[SkillContext] = None):
        self.cc = cc or SkillContext()

    def bundles(self) -> List[Dict]:
        cats: Dict[str, List[Dict]] = {}
        for s in self.cc.skill_map():
            cats.setdefault(s["category"], []).append(s)
        out = []
        for cat in sorted(cats):
            members = cats[cat]
            effs = [s["skill_effectiveness"] for s in members if s["skill_effectiveness"] is not None]
            out.append({
                "bundle_id": f"bundle_{cat}", "category": cat,
                "skills": sorted(s["skill_id"] for s in members), "skill_count": len(members),
                "capabilities": sorted({c for s in members for c in s["capabilities"]}),
                "capability_count": len({c for s in members for c in s["capabilities"]}),
                "agents": sorted({a for s in members for a in s["agents"]}),
                "effectiveness": round(mean(effs), 4) if effs else None, "advisory": True})
        out.sort(key=lambda b: (-(b["effectiveness"] or 0.0), b["bundle_id"]))
        return out

    def report(self) -> Dict:
        b = self.bundles()
        return {"bundles": b, "bundle_count": len(b), "advisory": True}
