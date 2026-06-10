"""
PlaybookGenerator (Phase Q) — materialize + score declarative campaign templates.

Each generated playbook exposes the four campaign facets (capabilities / skills / agents /
dependencies) and BOTH dual graphs (capability graph + skill graph), organized by campaign phase.
Advisory only — a planning scaffold, never an execution plan. Deterministic; O(C + D + S).
"""

from __future__ import annotations

from typing import Dict, List, Optional

from hydra.campaigns.campaign_model import CampaignContext, CampaignModel
from hydra.campaigns.campaign_templates import TEMPLATES, get_template
from hydra.campaigns.skill_bridge import CampaignSkillBridge


class PlaybookGenerator:
    def __init__(self, cc: Optional[CampaignContext] = None):
        self.cc = cc or CampaignContext()
        self.model = CampaignModel(self.cc)
        self.bridge = CampaignSkillBridge(self.cc)

    def _caps_for(self, template: Dict) -> List[str]:
        cats = set(template["categories"])
        return sorted(c.capability_id for c in self.cc.catalog().all() if c.category in cats)

    def generate(self, template: Dict) -> Dict:
        caps = self._caps_for(template)
        facets = self.bridge.facets(caps)
        capset = set(caps)
        phase_capabilities = {}
        for p in self.model.phases():
            if p.advisory_model_only or p.phase not in template["phases"]:
                continue
            sel = sorted(set(p.capabilities) & capset)
            if sel:
                phase_capabilities[p.phase] = sel
        return {
            "playbook_id": template["id"], "name": template["name"],
            "target_type": template.get("target_type"), "phases": template["phases"],
            "phase_capabilities": phase_capabilities,
            "effectiveness": facets["mean_effectiveness"],
            "capability_count": facets["capability_count"],
            "skill_count": facets["skill_count"], "agent_count": facets["agent_count"],
            "campaign_capabilities": facets["campaign_capabilities"],
            "campaign_skills": facets["campaign_skills"],
            "campaign_agents": facets["campaign_agents"],
            "campaign_dependencies": facets["campaign_dependencies"],
            "capability_graph": facets["capability_graph"],
            "skill_graph": facets["skill_graph"],
            "model_only_phases": [p.phase for p in self.model.phases() if p.advisory_model_only],
            "advisory": True,
        }

    def all_playbooks(self) -> List[Dict]:
        return [self.generate(t) for t in TEMPLATES]

    def get(self, playbook_id: str) -> Optional[Dict]:
        t = get_template(playbook_id)
        return self.generate(t) if t else None

    def summary(self) -> Dict:
        rows = [{"playbook_id": p["playbook_id"], "name": p["name"],
                 "effectiveness": p["effectiveness"], "capability_count": p["capability_count"],
                 "skill_count": p["skill_count"], "agent_count": p["agent_count"]}
                for p in self.all_playbooks()]
        rows.sort(key=lambda d: (-d["effectiveness"], d["playbook_id"]))
        return {"playbooks": rows, "count": len(rows), "advisory": True}
