"""
AdversaryProfileModeler (Phase T) — how well Hydra supports modelled adversary profiles.

Declarative adversary profiles, each a set of ATT&CK techniques characteristic of that actor, scored
against Hydra's technique coverage. Profiles are left-of-boom / recon-and-bug-bounty oriented (Hydra's
domain). "Support" = the mean best-effectiveness of the profile's in-scope techniques + the fraction
that are covered. Deterministic, read-only, advisory; NON-executing — modelling an adversary is not
emulating one.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from hydra.adversary_intel.context import AdversaryContext
from hydra.adversary_intel.technique_coverage import TechniqueCoverageAnalyzer
from hydra.adversary_intel.util import COVERED, WEAK, mean

# (profile_id, name, description, technique_ids)
_PROFILES: List[Tuple[str, str, str, Tuple[str, ...]]] = [
    ("external_recon_operator", "External Reconnaissance Operator",
     "Maps an organization's external footprint before any intrusion.",
     ("T1595", "T1590", "T1590.002", "T1590.005", "T1591", "T1592", "T1596", "T1046", "T1018")),
    ("web_app_attacker", "Web Application Attacker",
     "Finds and validates exploitable web/API weaknesses on public-facing apps.",
     ("T1190", "T1595.002", "T1083", "T1087", "T1110", "T1212")),
    ("cloud_attacker", "Cloud Attacker",
     "Enumerates cloud assets and harvests cloud credentials/metadata.",
     ("T1526", "T1538", "T1552.005", "T1078")),
    ("credential_harvester", "Credential Harvester",
     "Locates exposed secrets, keys and valid accounts across code and infra.",
     ("T1552", "T1552.001", "T1078", "T1589", "T1213")),
    ("supply_chain_recon", "Supply-Chain Recon Actor",
     "Probes third-party/dependency trust relationships and repositories.",
     ("T1199", "T1593", "T1213", "T1591")),
    ("attack_surface_mapper", "Attack-Surface Mapper",
     "Builds the full reachable service/host/endpoint surface.",
     ("T1595", "T1590", "T1592", "T1594", "T1046", "T1133")),
]


class AdversaryProfileModeler:
    def __init__(self, ac: Optional[AdversaryContext] = None,
                 techniques: Optional[TechniqueCoverageAnalyzer] = None):
        self.ac = ac or AdversaryContext()
        self.techniques = techniques or TechniqueCoverageAnalyzer(self.ac)

    def _rows(self) -> List[Dict]:
        cov = {r.technique_id: r for r in self.techniques.rank()}
        rows: List[Dict] = []
        for pid, name, desc, tids in _PROFILES:
            present = [cov[t] for t in tids if t in cov]
            in_scope = [c for c in present if not c.model_only]
            covered = [c for c in in_scope if c.status == COVERED]
            weak = [c for c in in_scope if c.status == WEAK]
            effs = [c.best_effectiveness for c in in_scope]
            denom = len(in_scope) or 1
            support = round(0.6 * mean(effs) + 0.4 * (len(covered) / denom), 4) if in_scope else 0.0
            rows.append({
                "profile_id": pid, "name": name, "description": desc,
                "techniques": list(tids), "technique_count": len(tids),
                "in_scope": len(in_scope), "covered": len(covered), "weak": len(weak),
                "uncovered": len(in_scope) - len(covered) - len(weak),
                "supported_pct": round(100 * len(covered) / denom, 1) if in_scope else 0.0,
                "support_score": support, "advisory": True,
            })
        rows.sort(key=lambda r: (-r["support_score"], r["profile_id"]))
        return rows

    def get(self, profile_id: str) -> Optional[Dict]:
        return next((r for r in self._rows() if r["profile_id"] == profile_id), None)

    def report(self, profile_id: str = "") -> Dict:
        if profile_id:
            r = self.get(profile_id)
            return (r if r else
                    {"profile_id": profile_id, "error": "unknown profile", "advisory": True})
        rows = self._rows()
        return {
            "profiles": rows, "count": len(rows),
            "best_supported": [r["profile_id"] for r in rows[:3]],
            "least_supported": [r["profile_id"] for r in rows[-3:][::-1]],
            "advisory": True,
        }
