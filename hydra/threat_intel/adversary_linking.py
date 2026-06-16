"""
AdversaryLinker (Phase U) — fuse Threats ↔ adversary profiles (Phase T).

Links each threat (ATT&CK tactic) to the adversary profiles that exercise its techniques, and
inverts that to show which profiles span the most threats. Read-only, advisory; O(threats × profiles)
over the tiny static sets. NON-executing — modelling adversaries, never emulating them.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from hydra.threat_intel.context import ThreatContext
from hydra.threat_intel.threat_model import ThreatModel


class AdversaryLinker:
    def __init__(self, tc: Optional[ThreatContext] = None, model: Optional[ThreatModel] = None):
        self.tc = tc or ThreatContext()
        self.model = model or ThreatModel(self.tc)

    def report(self) -> Dict:
        threats = self.model.in_scope()
        prof_rows = self.tc.adversary().profiles._rows()
        prof_support = {p["profile_id"]: p["support_score"] for p in prof_rows}

        per_threat = [{"threat_id": t.threat_id, "name": t.name,
                       "adversary_profiles": t.adversary_profiles,
                       "profile_count": len(t.adversary_profiles)} for t in threats]
        # invert: profile → threats
        by_profile: Dict[str, List[str]] = {}
        for t in threats:
            for p in t.adversary_profiles:
                by_profile.setdefault(p, []).append(t.threat_id)
        per_profile = [{"profile_id": p, "support_score": prof_support.get(p, 0.0),
                        "threats": sorted(ts), "threat_count": len(ts)}
                       for p, ts in by_profile.items()]
        per_profile.sort(key=lambda r: (-r["threat_count"], -r["support_score"], r["profile_id"]))
        per_threat.sort(key=lambda r: (-r["profile_count"], r["threat_id"]))
        return {
            "threats": per_threat, "profiles": per_profile,
            "most_targeted_threats": [r["threat_id"] for r in per_threat[:5]],
            "broadest_profiles": [r["profile_id"] for r in per_profile[:3]],
            "advisory": True,
        }
