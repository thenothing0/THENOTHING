"""
AttackGapAnalyzer (Phase T) — ATT&CK coverage gaps + how to close them.

Surfaces weakly-covered and uncovered in-scope techniques, weak tactics, the Phase-Q campaign phases
whose technique coverage is thin, and — bridging Phase S — the offensive OPPORTUNITIES (capabilities)
whose improvement would lift the most ATT&CK coverage. Deterministic, read-only, advisory;
NON-executing. Model-only (post-exploitation / out-of-scope) techniques are never counted as gaps.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from hydra.adversary_intel.context import AdversaryContext
from hydra.adversary_intel.tactic_coverage import TacticCoverageAnalyzer
from hydra.adversary_intel.technique_coverage import TechniqueCoverageAnalyzer
from hydra.adversary_intel.util import COVERED, UNCOVERED, WEAK, WEAK_EFFECTIVENESS

WEAK_TACTIC_PCT = 50.0


class AttackGapAnalyzer:
    def __init__(self, ac: Optional[AdversaryContext] = None,
                 techniques: Optional[TechniqueCoverageAnalyzer] = None,
                 tactics: Optional[TacticCoverageAnalyzer] = None):
        self.ac = ac or AdversaryContext()
        self.techniques = techniques or TechniqueCoverageAnalyzer(self.ac)
        self.tactics = tactics or TacticCoverageAnalyzer(self.ac, self.techniques)

    def weak_techniques(self) -> List[Dict]:
        return [r.to_dict() for r in self.techniques.rank() if r.status == WEAK]

    def uncovered_techniques(self) -> List[Dict]:
        return [r.to_dict() for r in self.techniques.rank() if r.status == UNCOVERED]

    def weak_tactics(self) -> List[Dict]:
        return [t for t in self.tactics.report()["tactics"]
                if not t["advisory_model_only"] and t["coverage_pct"] < WEAK_TACTIC_PCT]

    def campaign_paths_lacking_coverage(self) -> List[Dict]:
        """Per Phase-Q campaign phase, how many techniques in matching categories are covered."""
        cov = self.techniques.rank()
        rows: List[Dict] = []
        for phase in self.ac.campaign().model.phases():
            if phase.advisory_model_only:
                continue
            cats = set(phase.hydra_categories)
            techs = [c for c in cov if not c.model_only
                     and cats & set(self.ac.mapping().technique(c.technique_id).categories)]
            covered = [c for c in techs if c.status == COVERED]
            denom = len(techs) or 1
            rows.append({
                "phase": phase.phase, "categories": phase.hydra_categories,
                "techniques": len(techs), "covered": len(covered),
                "coverage_pct": round(100 * len(covered) / denom, 1) if techs else 0.0,
                "advisory": True})
        rows.sort(key=lambda r: (r["coverage_pct"], r["phase"]))
        return rows

    def opportunities_improving_coverage(self, limit: int = 10) -> List[Dict]:
        """Phase-S opportunities (capabilities) backing weak techniques, ranked by opportunity score —
        strengthening these lifts ATT&CK coverage the most."""
        opp = {o.opportunity_id: o.score for o in self.ac.opportunity().ranker.rank()}
        backing: Dict[str, List[str]] = {}
        for r in self.techniques.rank():
            if r.status == WEAK:
                for cap in r.capabilities:
                    backing.setdefault(cap, []).append(r.technique_id)
        rows = [{"capability_id": cap, "opportunity_score": round(opp.get(cap, 0.0), 4),
                 "techniques_helped": sorted(t), "technique_count": len(t), "advisory": True}
                for cap, t in backing.items()]
        rows.sort(key=lambda r: (-r["opportunity_score"], -r["technique_count"], r["capability_id"]))
        return rows[:max(1, limit)]

    def report(self) -> Dict:
        wt = self.weak_techniques()
        ut = self.uncovered_techniques()
        wtac = self.weak_tactics()
        return {
            "weak_techniques": wt, "weak_technique_count": len(wt),
            "uncovered_techniques": ut, "uncovered_technique_count": len(ut),
            "weak_tactics": wtac, "weak_tactic_count": len(wtac),
            "campaign_paths_lacking_coverage": self.campaign_paths_lacking_coverage(),
            "opportunities_improving_coverage": self.opportunities_improving_coverage(),
            "weak_effectiveness_threshold": WEAK_EFFECTIVENESS, "advisory": True,
        }
