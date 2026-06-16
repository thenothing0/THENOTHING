"""
TacticCoverageAnalyzer (Phase T) — per-ATT&CK-tactic coverage.

Aggregates technique coverage up to the 14 ATT&CK Enterprise tactics: covered / weak / uncovered
technique counts, a coverage percentage (over in-scope techniques), and mean effectiveness.
Model-only tactics (Resource Development, Execution, the post-exploitation chain, Impact) are flagged
and excluded from the coverage denominator — they are intentionally uncovered, never a defect.
Deterministic, read-only, advisory; O(T).
"""

from __future__ import annotations

from typing import Dict, List, Optional

from hydra.adversary_intel.context import AdversaryContext
from hydra.adversary_intel.technique_coverage import TechniqueCoverageAnalyzer
from hydra.adversary_intel.util import COVERED, WEAK, mean


class TacticCoverageAnalyzer:
    def __init__(self, ac: Optional[AdversaryContext] = None,
                 techniques: Optional[TechniqueCoverageAnalyzer] = None):
        self.ac = ac or AdversaryContext()
        self.techniques = techniques or TechniqueCoverageAnalyzer(self.ac)

    def _rows(self) -> List[Dict]:
        cov = {r.technique_id: r for r in self.techniques.rank()}
        rows: List[Dict] = []
        for tac in self.ac.mapping().tactics():
            techs = self.ac.mapping().techniques_for_tactic(tac.tactic_id)
            tcovs = [cov[t.technique_id] for t in techs if t.technique_id in cov]
            in_scope = [c for c in tcovs if not c.model_only]
            covered = [c for c in in_scope if c.status == COVERED]
            weak = [c for c in in_scope if c.status == WEAK]
            effs = [c.best_effectiveness for c in covered]
            denom = len(in_scope)
            rows.append({
                "tactic_id": tac.tactic_id, "name": tac.name,
                "hydra_coverage": tac.hydra_coverage,
                "advisory_model_only": tac.advisory_model_only,
                "techniques": len(techs), "in_scope": denom,
                "covered": len(covered), "weak": len(weak),
                "uncovered": denom - len(covered) - len(weak),
                "coverage_pct": round(100 * len(covered) / denom, 1) if denom else 0.0,
                "mean_effectiveness": round(mean(effs), 4) if effs else 0.0,
                "advisory": True,
            })
        return rows

    def report(self) -> Dict:
        rows = self._rows()
        covered_tactics = [r for r in rows if not r["advisory_model_only"]]
        ranked = sorted(covered_tactics, key=lambda r: (-r["coverage_pct"], r["tactic_id"]))
        return {
            "tactics": rows, "count": len(rows),
            "hydra_covered_tactics": [r["tactic_id"] for r in covered_tactics],
            "model_only_tactics": [r["tactic_id"] for r in rows if r["advisory_model_only"]],
            "strongest_tactics": ranked[:5],
            "weakest_tactics": list(reversed(ranked[-5:])) if len(ranked) >= 1 else [],
            "advisory": True,
        }
