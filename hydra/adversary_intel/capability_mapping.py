"""
CapabilityTechniqueMapper (Phase T) — which capabilities provide the strongest technique coverage.

Inverts the ATT&CK mapping (technique → capabilities) into capability → techniques, then scores each
capability's ATT&CK contribution as effectiveness × technique-breadth. Deterministic, read-only,
advisory; O(T·C) bounded by the small static technique set.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from hydra.adversary_intel.context import AdversaryContext
from hydra.adversary_intel.util import norm


class CapabilityTechniqueMapper:
    def __init__(self, ac: Optional[AdversaryContext] = None):
        self.ac = ac or AdversaryContext()
        self._rows_cache: Optional[List[Dict]] = None

    def _rows(self) -> List[Dict]:
        if self._rows_cache is not None:
            return self._rows_cache
        mapping = self.ac.mapping()
        emap = self.ac.eff_map()
        cap_techs: Dict[str, List[str]] = {}
        cap_tactics: Dict[str, set] = {}
        for t in mapping.techniques():
            if t.model_only:
                continue
            for cap in mapping.capabilities_for(t):
                cap_techs.setdefault(cap, []).append(t.technique_id)
                cap_tactics.setdefault(cap, set()).add(t.tactic_id)
        max_techs = max((len(v) for v in cap_techs.values()), default=1) or 1
        rows: List[Dict] = []
        for cap in sorted(cap_techs):
            techs = sorted(cap_techs[cap])
            eff = emap[cap].effectiveness if cap in emap else 0.0
            ce = emap.get(cap)
            rows.append({
                "capability_id": cap, "category": ce.category if ce else "",
                "techniques": techs, "technique_count": len(techs),
                "tactics": sorted(cap_tactics[cap]), "tactic_count": len(cap_tactics[cap]),
                "effectiveness": round(eff, 4),
                "coverage_strength": round(eff * norm(len(techs), max_techs), 4),
                "advisory": True,
            })
        rows.sort(key=lambda r: (-r["coverage_strength"], -r["technique_count"], r["capability_id"]))
        self._rows_cache = rows
        return rows

    def get(self, capability_id: str) -> Optional[Dict]:
        return next((r for r in self._rows() if r["capability_id"] == capability_id), None)

    def report(self, limit: int = 25) -> Dict:
        rows = self._rows()
        return {
            "capabilities": rows[:max(1, limit)], "count": len(rows),
            "top": [r["capability_id"] for r in rows[:5]],
            "advisory": True,
        }
