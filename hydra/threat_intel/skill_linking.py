"""
SkillLinker (Phase U) — fuse Threats ↔ skills (Phase R).

Answers: which skills matter most (touch the most threats), which are underrepresented (touch few),
and which skill gaps create the largest threat exposure (high-risk threats backed by few skills).
Read-only, advisory; O(threats × skills) over the small skill set.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from hydra.threat_intel.context import ThreatContext
from hydra.threat_intel.threat_model import ThreatModel
from hydra.threat_intel.util import mean


class SkillLinker:
    def __init__(self, tc: Optional[ThreatContext] = None, model: Optional[ThreatModel] = None):
        self.tc = tc or ThreatContext()
        self.model = model or ThreatModel(self.tc)

    def report(self) -> Dict:
        threats = self.model.in_scope()
        eff = {s["skill_id"]: s["skill_effectiveness"] for s in self.tc.skill().cc.skill_map()}
        by_skill: Dict[str, List[str]] = {}
        for t in threats:
            for s in t.skills:
                by_skill.setdefault(s, []).append(t.threat_id)
        per_skill = [{"skill_id": s, "effectiveness": eff.get(s),
                      "threats": sorted(ts), "threat_count": len(ts)}
                     for s, ts in by_skill.items()]
        per_skill.sort(key=lambda r: (-r["threat_count"], r["skill_id"]))

        # threats whose exposure (high risk) rests on few skills = largest skill-gap exposure
        exposure = sorted(
            ({"threat_id": t.threat_id, "name": t.name, "risk_score": t.risk_score,
              "skill_count": len(t.skills), "skills": t.skills}
             for t in threats if t.risk_score is not None),
            key=lambda r: (-(r["risk_score"] or 0.0), r["skill_count"], r["threat_id"]))

        return {
            "skills": per_skill, "skill_count": len(per_skill),
            "most_critical_skills": [r["skill_id"] for r in per_skill[:5]],
            "underrepresented_skills": [r["skill_id"] for r in per_skill if r["threat_count"] <= 1][:5],
            "mean_skills_per_threat": round(mean([len(t.skills) for t in threats]), 4)
            if threats else 0.0,
            "skill_gap_exposure": exposure[:5],
            "advisory": True,
        }
