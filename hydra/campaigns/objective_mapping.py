"""
ObjectiveMapping (Phase Q) — Objective → Skills → Capabilities → Adapters → Agents.

A declarative objective catalog maps each objective to Hydra capability categories, then produces an
explainable chain down through skills, capabilities, adapters and owning agents. Deterministic,
advisory, read-only; O(C + S).
"""

from __future__ import annotations

from typing import Dict, List, Optional

from hydra.campaigns.campaign_model import CampaignContext

OBJECTIVES: List[Dict] = [
    {"id": "external_attack_surface", "name": "Map the external attack surface", "categories": ["reconnaissance"]},
    {"id": "web_vuln_candidates", "name": "Find web vulnerability candidates", "categories": ["web"]},
    {"id": "api_surface", "name": "Enumerate the API surface", "categories": ["api"]},
    {"id": "cloud_exposure", "name": "Discover cloud exposure", "categories": ["cloud"]},
    {"id": "leaked_secrets", "name": "Discover leaked secrets / source exposure", "categories": ["secrets", "source_code"]},
    {"id": "verify_findings", "name": "Verify candidate findings", "categories": ["verification"]},
]


def get_objective(objective_id: str) -> Optional[Dict]:
    return next((o for o in OBJECTIVES if o["id"] == objective_id), None)


class ObjectiveMapping:
    def __init__(self, cc: Optional[CampaignContext] = None):
        self.cc = cc or CampaignContext()

    def _adapters_for(self, capability_id: str) -> List[str]:
        try:
            return sorted(a.adapter_id for a in self.cc.ctx.adapters().adapters_for_capability(capability_id))
        except Exception:
            return []

    def map_objective(self, objective: Dict) -> Dict:
        cats = set(objective["categories"])
        cat = self.cc.catalog()
        emap = self.cc.eff_map()
        owner = self.cc.owner_of()
        caps = sorted(c.capability_id for c in cat.all() if c.category in cats)
        capset = set(caps)
        skills = sorted({s["skill_id"] for s in self.cc.skill_map() if set(s["capabilities"]) & capset})
        agents = sorted({owner.get(cid) for cid in caps if owner.get(cid)})
        chain = sorted(
            [{"capability_id": cid,
              "effectiveness": emap[cid].effectiveness if cid in emap else None,
              "adapters": self._adapters_for(cid), "owner_agent": owner.get(cid)} for cid in caps],
            key=lambda d: (-(d["effectiveness"] or 0.0), d["capability_id"]))
        return {
            "objective": objective["id"], "name": objective["name"],
            "skills": skills, "capabilities": [c["capability_id"] for c in chain],
            "agents": agents, "chain": chain,
            "explanation": (f"objective '{objective['id']}' → {len(skills)} skills → "
                            f"{len(caps)} capabilities → adapters → {len(agents)} agents"),
            "advisory": True,
        }

    def all_objectives(self) -> List[Dict]:
        return [self.map_objective(o) for o in OBJECTIVES]

    def report(self) -> Dict:
        return {"objectives": [{"objective": o["id"], "name": o["name"]} for o in OBJECTIVES],
                "count": len(OBJECTIVES), "advisory": True}
