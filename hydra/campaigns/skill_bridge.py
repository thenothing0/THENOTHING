"""
CampaignSkillBridge (Phase Q) — make Skills first-class planning entities.

For ANY capability set (a campaign / playbook / objective) it produces the four campaign facets —
`campaign_capabilities`, `campaign_skills`, `campaign_agents`, `campaign_dependencies` — and BOTH a
`capability_graph` and a `skill_graph`, so a campaign is explainable as a Capability Graph AND a
Skill Graph. Reuses the Phase-P skill bridge (31 declarative skills). Deterministic, advisory,
read-only. Bounded: O(C + D + S) with S ≤ #skills (a small constant).
"""

from __future__ import annotations

from typing import Dict, List, Optional

from hydra.campaigns.campaign_model import CampaignContext
from hydra.campaigns.util import mean


class CampaignSkillBridge:
    def __init__(self, cc: Optional[CampaignContext] = None):
        self.cc = cc or CampaignContext()

    def _skills_for(self, cap_ids: set) -> List[Dict]:
        rows = []
        for s in self.cc.skill_map():
            shared = sorted(set(s["capabilities"]) & cap_ids)
            if shared:
                rows.append({"skill_id": s["skill_id"], "name": s["name"], "category": s["category"],
                             "capabilities": shared, "capability_count": len(shared),
                             "skill_effectiveness": s["skill_effectiveness"],
                             "agents": s["agents"], "chain_to": s["chain_to"]})
        rows.sort(key=lambda r: (-(r["skill_effectiveness"] or 0.0), r["skill_id"]))
        return rows

    def facets(self, capabilities) -> Dict:
        cat = self.cc.catalog()
        emap = self.cc.eff_map()
        owner = self.cc.owner_of()
        present = sorted(cid for cid in set(capabilities) if cat.get(cid))
        present_set = set(present)

        caps = [{"capability_id": cid, "category": cat.get(cid).category,
                 "effectiveness": emap[cid].effectiveness if cid in emap else None,
                 "verification_capable": cat.get(cid).is_verification,
                 "owner_agent": owner.get(cid)} for cid in present]
        skills = self._skills_for(present_set)
        agents = sorted({owner.get(cid) for cid in present if owner.get(cid)})

        deps = sorted([e for e in self.cc.graph().edges()
                       if e["relation"] in ("requires", "enhances")
                       and e["from"] in present_set and e["to"] in present_set],
                      key=lambda e: (e["relation"], e["from"], e["to"]))
        cap_edges = [{"from": e["from"], "to": e["to"], "relation": e["relation"]} for e in deps]
        capability_graph = {"nodes": present, "edges": cap_edges}

        # skill graph: chain_to edges + shared-capability edges (S bounded ⇒ O(S^2) is constant)
        sids = {s["skill_id"] for s in skills}
        sk_caps = {s["skill_id"]: set(s["capabilities"]) for s in skills}
        sk_edges = [{"from": s["skill_id"], "to": ct, "relation": "chain_to"}
                    for s in skills for ct in s["chain_to"] if ct in sids]
        slist = sorted(sk_caps)
        for i in range(len(slist)):
            for j in range(i + 1, len(slist)):
                a, b = slist[i], slist[j]
                if sk_caps[a] & sk_caps[b]:
                    sk_edges.append({"from": a, "to": b, "relation": "shared_capability"})
        sk_edges.sort(key=lambda e: (e["relation"], e["from"], e["to"]))
        skill_graph = {"nodes": sorted(sids), "edges": sk_edges}

        eff_vals = [c["effectiveness"] for c in caps if c["effectiveness"] is not None]
        return {
            "campaign_capabilities": caps,
            "campaign_skills": skills,
            "campaign_agents": agents,
            "campaign_dependencies": cap_edges,
            "capability_graph": capability_graph,
            "skill_graph": skill_graph,
            "capability_count": len(caps), "skill_count": len(skills), "agent_count": len(agents),
            "mean_effectiveness": round(mean(eff_vals), 4) if eff_vals else 0.0,
            "advisory": True,
        }
