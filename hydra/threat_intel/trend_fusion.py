"""
ThreatEvolution (Phase U) — fuse Phase-O temporal signals with Phase-T ATT&CK coverage.

Identifies, deterministically and WITHOUT prediction beyond bounded signals:
  * rising threats     — backing capabilities are emerging (Phase-O) faster than declining;
  * declining threats  — backing capabilities are declining;
  * emerging patterns   — weakly-covered threats whose backing capabilities are emerging (growing
                          attention to an under-covered area — worth strengthening early).
In cold-start / offline (no temporal store) every threat is `stable` — an honest default, never a
fabricated trend. Read-only, advisory; O(threats).
"""

from __future__ import annotations

from typing import Dict, List, Optional

from hydra.threat_intel.context import ThreatContext
from hydra.threat_intel.threat_model import ThreatModel


def _direction(emerging: int, declining: int) -> str:
    if emerging > declining:
        return "rising"
    if declining > emerging:
        return "declining"
    return "stable"


class ThreatEvolution:
    def __init__(self, tc: Optional[ThreatContext] = None, model: Optional[ThreatModel] = None):
        self.tc = tc or ThreatContext()
        self.model = model or ThreatModel(self.tc)

    def _rows(self) -> List[Dict]:
        rows: List[Dict] = []
        for t in self.model.in_scope():
            ne, nd = len(t.emerging_capabilities), len(t.declining_capabilities)
            rows.append({
                "threat_id": t.threat_id, "name": t.name,
                "direction": _direction(ne, nd),
                "emerging_capabilities": t.emerging_capabilities,
                "declining_capabilities": t.declining_capabilities,
                "decay": t.decay, "coverage_ratio": t.coverage_ratio,
                "risk_status": t.risk_status,
                "emerging_pattern": bool(ne > 0 and t.risk_status in ("high", "moderate")),
                "advisory": True})
        rows.sort(key=lambda r: ({"rising": 0, "stable": 1, "declining": 2}[r["direction"]],
                                 -len(r["emerging_capabilities"]), r["threat_id"]))
        return rows

    def report(self) -> Dict:
        rows = self._rows()
        return {
            "threats": rows, "count": len(rows),
            "rising": [r["threat_id"] for r in rows if r["direction"] == "rising"],
            "declining": [r["threat_id"] for r in rows if r["direction"] == "declining"],
            "stable": [r["threat_id"] for r in rows if r["direction"] == "stable"],
            "emerging_patterns": [r["threat_id"] for r in rows if r["emerging_pattern"]],
            "temporal_data": self.tc.total_events() > 0
            or bool(self.tc.temporal_signal()["emerging"] or self.tc.temporal_signal()["declining"]),
            "advisory": True,
        }
