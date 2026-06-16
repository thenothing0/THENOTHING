"""
OpportunityLinker (Phase U) — fuse Threats ↔ opportunities (Phase S).

Answers: which threats expose capability gaps, which threats have weak coverage, and which
offensive opportunities would close the most risk. An opportunity "closes risk" in proportion to
its Phase-S score AND the aggregate risk of the threats whose backing capabilities it improves.
Read-only, advisory; O(threats + capabilities).
"""

from __future__ import annotations

from typing import Dict, List, Optional

from hydra.threat_intel.context import ThreatContext
from hydra.threat_intel.threat_model import ThreatModel
from hydra.threat_intel.util import clamp01


class OpportunityLinker:
    def __init__(self, tc: Optional[ThreatContext] = None, model: Optional[ThreatModel] = None):
        self.tc = tc or ThreatContext()
        self.model = model or ThreatModel(self.tc)

    def report(self) -> Dict:
        threats = [t for t in self.model.in_scope() if t.risk_score is not None]
        opp = {o.opportunity_id: o.score for o in self.tc.opportunity().ranker.rank()}

        # capability → aggregate risk of the threats it backs (risk-closing potential)
        cap_risk: Dict[str, float] = {}
        cap_threats: Dict[str, List[str]] = {}
        for t in threats:
            for cap in t.capabilities:
                cap_risk[cap] = cap_risk.get(cap, 0.0) + (t.risk_score or 0.0)
                cap_threats.setdefault(cap, []).append(t.threat_id)
        risk_closers = [{"capability_id": c, "opportunity_score": round(opp.get(c, 0.0), 4),
                         "threats_helped": sorted(cap_threats[c]),
                         "threat_count": len(cap_threats[c]),
                         "risk_closed": round(clamp01(opp.get(c, 0.0)) * cap_risk[c], 4)}
                        for c in cap_risk]
        risk_closers.sort(key=lambda r: (-r["risk_closed"], -r["threat_count"], r["capability_id"]))

        exposed = sorted(
            ({"threat_id": t.threat_id, "name": t.name, "risk_score": t.risk_score,
              "risk_status": t.risk_status, "coverage_ratio": t.coverage_ratio,
              "opportunity_gap": t.opportunity_gap, "weak": t.weak, "uncovered": t.uncovered}
             for t in threats),
            key=lambda r: (-(r["risk_score"] or 0.0), r["threat_id"]))

        return {
            "exposed_threats": exposed,
            "weakly_covered_threats": [r["threat_id"] for r in exposed
                                       if r["risk_status"] in ("high", "moderate")],
            "risk_closing_opportunities": risk_closers[:10],
            "advisory": True,
        }
