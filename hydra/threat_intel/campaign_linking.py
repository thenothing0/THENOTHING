"""
CampaignLinker (Phase U) — fuse Threats ↔ campaigns (Phase Q).

Answers: which campaign phases are best covered, which campaign paths are weakest, and which campaign
stages rely on FRAGILE (single-provider) capability coverage. A threat (tactic) links to a campaign
phase by SHARED CATEGORY (explained, never guessed). Read-only, advisory; O(threats × phases).
"""

from __future__ import annotations

from typing import Dict, List, Optional

from hydra.threat_intel.context import ThreatContext
from hydra.threat_intel.threat_model import ThreatModel
from hydra.threat_intel.util import mean


class CampaignLinker:
    def __init__(self, tc: Optional[ThreatContext] = None, model: Optional[ThreatModel] = None):
        self.tc = tc or ThreatContext()
        self.model = model or ThreatModel(self.tc)

    def report(self) -> Dict:
        threats = self.model.in_scope()
        phases = [p for p in self.tc.campaign().model.phases() if not p.advisory_model_only]
        rows: List[Dict] = []
        for ph in phases:
            linked = [t for t in threats if ph.phase in t.campaign_phases]
            cov = [t.coverage_ratio for t in linked]
            fragile = sum(t.fragile_techniques for t in linked)
            rows.append({
                "phase": ph.phase, "categories": ph.hydra_categories,
                "threats": sorted(t.threat_id for t in linked), "threat_count": len(linked),
                "mean_coverage": round(mean(cov), 4) if cov else 0.0,
                "fragile_techniques": fragile,
                "advisory": True})
        rows.sort(key=lambda r: (r["mean_coverage"], -r["fragile_techniques"], r["phase"]))
        return {
            "campaign_phases": rows, "count": len(rows),
            "weakest_paths": [r["phase"] for r in rows[:3]],
            "best_covered": [r["phase"] for r in reversed(rows[-3:])],
            "fragile_stages": sorted(
                ({"phase": r["phase"], "fragile_techniques": r["fragile_techniques"]}
                 for r in rows if r["fragile_techniques"] > 0),
                key=lambda r: (-r["fragile_techniques"], r["phase"])),
            "advisory": True,
        }
