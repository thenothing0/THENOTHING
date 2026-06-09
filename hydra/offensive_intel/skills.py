"""
SkillIntelligence (Phase P) — Capability → Skill → Workflow → Agent bridge (read-only).

Maps each declarative skill (skills/<slug>/SKILL.yaml) to the capabilities it activates (by
category, refined when the skill slug matches a finding-type), then to the owning agents, and
scores skill effectiveness/quality from the underlying capability effectiveness. Concept inspired
by cybersecurity-skills modeling; it MAPS and SCORES skills — it never activates or executes them.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from hydra.offensive_intel.context import OffensiveContext
from hydra.offensive_intel.effectiveness import CapabilityEffectivenessEngine
from hydra.offensive_intel.util import mean


class SkillIntelligence:
    def __init__(self, ctx: Optional[OffensiveContext] = None,
                 engine: Optional[CapabilityEffectivenessEngine] = None):
        self.ctx = (ctx or OffensiveContext()).load()
        self.engine = engine or CapabilityEffectivenessEngine(self.ctx)

    def skill_map(self) -> List[Dict]:
        cat = self.ctx.catalog()
        emap = self.engine.as_map()
        owner = self.ctx.owner_of()
        rows = []
        for s in self.ctx.skills():
            members = cat.by_category(s["category"])
            slug = s["slug"]
            refined = [c for c in members
                       if slug in c.supported_finding_types or slug in c.capability_id]
            mapped = refined or members
            cap_ids = sorted(c.capability_id for c in mapped)
            effs = [emap[cid].effectiveness for cid in cap_ids if cid in emap]
            verif = sum(1 for cid in cap_ids if cid in emap and emap[cid].verification_capable)
            agents = sorted({owner.get(cid) for cid in cap_ids if owner.get(cid)})
            skill_eff = round(mean(effs), 4) if effs else None
            quality = round((skill_eff or 0.0) * (verif / len(cap_ids)), 4) if cap_ids else 0.0
            rows.append({
                "skill_id": s["skill_id"], "name": s["name"], "category": s["category"],
                "capabilities": cap_ids, "capability_count": len(cap_ids),
                "agents": agents, "skill_effectiveness": skill_eff,
                "verification_capable_caps": verif, "skill_quality": quality,
                "refined": bool(refined), "mcp_tools": s["mcp_tools"],
                "chain_to": s["chain_to"], "advisory": True,
            })
        rows.sort(key=lambda d: (-(d["skill_effectiveness"] or 0.0), d["skill_id"]))
        return rows

    def report(self) -> Dict:
        rows = self.skill_map()
        bridged = sum(1 for r in rows if r["capability_count"] > 0)
        return {"skills": rows, "skill_count": len(rows), "bridged_skills": bridged,
                "unbridged_skills": len(rows) - bridged, "advisory": True}
