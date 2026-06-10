"""
CampaignSimulator (Phase Q) — counterfactual campaign impact.

Reasons about "what if" without any runtime execution or target interaction: remove a capability,
remove a plugin, drop verification quality, or remove a category — then recompute campaign coverage
and effectiveness deltas over the Hydra-covered phases. Deterministic, bounded (O(C) per scenario),
advisory, NON-executing.
"""

from __future__ import annotations

from typing import Dict, Optional

from hydra.campaigns.campaign_model import CampaignContext, CampaignModel
from hydra.campaigns.util import mean

SCENARIOS = ("remove_capability", "remove_plugin", "verification_drop", "category_change")
_VERIFICATION_DROP_FACTOR = 0.5


class CampaignSimulator:
    def __init__(self, cc: Optional[CampaignContext] = None):
        self.cc = cc or CampaignContext()
        self.model = CampaignModel(self.cc)

    def _baseline(self) -> Dict[str, set]:
        return {p.phase: set(p.capabilities) for p in self.model.phases()
                if not p.advisory_model_only}

    def simulate(self, scenario: str = "remove_capability", subject: str = "") -> Dict:
        cat = self.cc.catalog()
        emap = self.cc.eff_map()
        base = self._baseline()
        all_base = sorted({c for caps in base.values() for c in caps})
        base_eff = mean([emap[c].effectiveness for c in all_base if c in emap]) if all_base else 0.0

        removed: set = set()
        note = "no-op (unknown scenario/subject)"
        if scenario == "remove_capability" and subject:
            removed, note = {subject}, f"capability '{subject}' unavailable"
        elif scenario == "remove_plugin" and subject:
            removed = {cid for cid, pl in self.cc.owner_plugin().items() if pl == subject}
            note = f"plugin '{subject}' removed ({len(removed)} capabilities)"
        elif scenario == "category_change" and subject:
            removed = {c.capability_id for c in cat.by_category(subject)}
            note = f"category '{subject}' coverage removed"

        proj = {ph: caps - removed for ph, caps in base.items()}
        all_proj = sorted({c for caps in proj.values() for c in caps})
        if scenario == "verification_drop":
            proj_eff = mean([emap[c].effectiveness * (_VERIFICATION_DROP_FACTOR
                                                      if cat.get(c) and cat.get(c).is_verification else 1.0)
                             for c in all_proj if c in emap]) if all_proj else 0.0
            note = f"verification effectiveness × {_VERIFICATION_DROP_FACTOR}"
        else:
            proj_eff = mean([emap[c].effectiveness for c in all_proj if c in emap]) if all_proj else 0.0

        impacted = sorted(ph for ph in base if base[ph] != proj.get(ph, set()))
        return {
            "scenario": scenario, "subject": subject, "note": note,
            "baseline_capabilities": len(all_base), "projected_capabilities": len(all_proj),
            "capabilities_lost": len(all_base) - len(all_proj),
            "baseline_effectiveness": round(base_eff, 4),
            "projected_effectiveness": round(proj_eff, 4),
            "effectiveness_delta": round(proj_eff - base_eff, 4),
            "impacted_phases": impacted, "non_executing": True, "advisory": True,
        }

    def report(self) -> Dict:
        return {"available_scenarios": list(SCENARIOS), "non_executing": True, "advisory": True}
