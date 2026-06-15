"""
AttackSurfaceModel (Phase S) — models Hydra's OWN modelled offensive reach.

This is a NON-executing MODEL of the offensive surface Hydra can address — organized by capability
category, with the distinct finding-types and target-types each category reaches, its mean
effectiveness, verification capability, and how much of it has actually been exercised. It is NOT a
live scan of any target and never touches one; it summarizes the declarative capability catalog
joined with the Phase-P effectiveness/exercise rollups. Deterministic, read-only, advisory; O(C).
"""

from __future__ import annotations

from typing import Dict, List, Optional

from hydra.opportunity_intel.context import OpportunityContext
from hydra.opportunity_intel.util import mean


class AttackSurfaceModel:
    def __init__(self, oc: Optional[OpportunityContext] = None):
        self.oc = oc or OpportunityContext()
        self._rows: Optional[List[Dict]] = None

    def _category_rows(self) -> List[Dict]:
        if self._rows is not None:
            return self._rows
        cat = self.oc.catalog()
        emap = self.oc.eff_map()
        rows: List[Dict] = []
        for category in sorted({c.category for c in cat.all()}):
            members = cat.by_category(category)
            n = len(members)
            fts = sorted({ft for c in members for ft in c.supported_finding_types})
            tts = sorted({tt for c in members for tt in c.supported_target_types})
            effs = [emap[c.capability_id].effectiveness for c in members if c.capability_id in emap]
            verif = sum(1 for c in members if c.is_verification)
            exercised = sum(1 for c in members
                            if (o := self.oc.ctx.capability_outcome(c.capability_id)) and o.events > 0)
            rows.append({
                "category": category, "capabilities": n,
                "finding_types": fts, "finding_type_count": len(fts),
                "target_types": tts, "target_type_count": len(tts),
                "mean_effectiveness": round(mean(effs), 4) if effs else 0.0,
                "verification_capable": verif,
                "verification_coverage_pct": round(100 * verif / n, 1) if n else 0.0,
                "exercised": exercised,
                "exercised_pct": round(100 * exercised / n, 1) if n else 0.0,
                "advisory": True,
            })
        rows.sort(key=lambda d: (-d["finding_type_count"], -d["mean_effectiveness"], d["category"]))
        self._rows = rows
        return rows

    def totals(self) -> Dict:
        cat = self.oc.catalog()
        caps = cat.all()
        all_fts = {ft for c in caps for ft in c.supported_finding_types}
        all_tts = {tt for c in caps for tt in c.supported_target_types}
        breadths = [len(c.supported_finding_types) + len(c.supported_target_types) for c in caps]
        exercised = sum(1 for c in caps
                        if (o := self.oc.ctx.capability_outcome(c.capability_id)) and o.events > 0)
        n = len(caps)
        return {
            "total_capabilities": n,
            "categories": len({c.category for c in caps}),
            "addressable_finding_types": len(all_fts),
            "addressable_target_types": len(all_tts),
            "verification_capable": sum(1 for c in caps if c.is_verification),
            "exercised_capabilities": exercised,
            "exercised_pct": round(100 * exercised / n, 1) if n else 0.0,
            "mean_capability_breadth": round(mean(breadths), 4) if breadths else 0.0,
        }

    def report(self) -> Dict:
        rows = self._category_rows()
        t = self.totals()
        # Surface breadth index: how much of the addressable surface is actually exercised.
        breadth_index = round(t["exercised_pct"] / 100.0, 4)
        return {
            "surface": rows, "totals": t,
            "widest_categories": [{"category": r["category"],
                                   "finding_type_count": r["finding_type_count"]} for r in rows[:5]],
            "surface_breadth_index": breadth_index,
            "advisory": True,
        }
