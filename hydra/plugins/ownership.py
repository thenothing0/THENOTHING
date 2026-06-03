"""
AgentOwnershipResolver (Phase M) — automatic agent ownership of (plugin) capabilities.

Resolves which Phase-H agent owns each capability. A plugin capability may declare a
`preferred_agent`; otherwise ownership is resolved automatically from the capability's
category against each agent's allowed categories (the existing Phase-H ownership rule).
Reports ownership conflicts, gaps, and a deterministic ownership confidence.

Read-only / advisory: never executes, never writes the wiki, never mutates agents.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from hydra.agents.registry import AgentRegistry
from hydra.capabilities.capability_catalog import CapabilityCatalog


class AgentOwnershipResolver:
    def __init__(self, catalog: Optional[CapabilityCatalog] = None,
                 agents: Optional[AgentRegistry] = None,
                 preferred: Optional[Dict[str, str]] = None):
        self.catalog = (catalog or CapabilityCatalog()).load()
        self.agents = (agents or AgentRegistry(capability_catalog=self.catalog)).load()
        self.preferred = preferred or {}          # capability_id → preferred_agent
        self._agent_ids = {a.agent_id for a in self.agents.all()}

    def _category_owners(self) -> Dict[str, List[str]]:
        """capability_id → agent_ids whose allowed categories cover its category."""
        owners: Dict[str, List[str]] = {}
        for a in self.agents.all():
            if a.knowledge_agent:
                continue
            for c in a.owned_capabilities(self.catalog):
                owners.setdefault(c.capability_id, []).append(a.agent_id)
        return owners

    def resolve(self) -> Dict:
        cat_owners = self._category_owners()
        assignments: List[Dict] = []
        conflicts: List[Dict] = []
        gaps: List[str] = []

        for cap in self.catalog.all():
            cid = cap.capability_id
            candidates = sorted(cat_owners.get(cid, []))
            pref = self.preferred.get(cid)
            pref_valid = bool(pref) and pref in self._agent_ids

            if pref_valid:
                owner = pref
                # conflict if the declared preference is NOT a natural category owner
                if candidates and pref not in candidates:
                    confidence = "medium"
                    conflicts.append({"capability_id": cid, "preferred_agent": pref,
                                      "category_owners": candidates,
                                      "reason": "preferred_agent overrides category ownership"})
                else:
                    confidence = "high"
            elif pref and not pref_valid:
                owner = candidates[0] if candidates else None
                confidence = "low"
                conflicts.append({"capability_id": cid, "preferred_agent": pref,
                                  "category_owners": candidates,
                                  "reason": "preferred_agent does not exist"})
            elif len(candidates) == 1:
                owner, confidence = candidates[0], "high"
            elif len(candidates) > 1:
                owner, confidence = candidates[0], "medium"
                conflicts.append({"capability_id": cid, "category_owners": candidates,
                                  "reason": "multiple agents claim this category"})
            else:
                owner, confidence = None, "low"
                gaps.append(cid)

            assignments.append({"capability_id": cid, "category": cap.category,
                                "owner": owner, "candidates": candidates,
                                "ownership_confidence": confidence})

        assignments.sort(key=lambda d: d["capability_id"])
        return {
            "total_capabilities": len(assignments),
            "owned": sum(1 for a in assignments if a["owner"]),
            "ownership_gaps": sorted(gaps),
            "ownership_gap_count": len(gaps),
            "ownership_conflicts": sorted(conflicts, key=lambda d: d["capability_id"]),
            "ownership_conflict_count": len(conflicts),
            "assignments": assignments,
        }
