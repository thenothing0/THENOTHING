"""
OffensiveCoverageAnalyzer (Phase P) — category / workflow / attack-path coverage.

Category coverage = per-category effectiveness, verification coverage, exercise rate, agent
ownership. Workflow coverage = how many capabilities an agent owns (orphans are uncovered).
Attack-path coverage = dependency edges whose both endpoints have been exercised. Deterministic,
advisory only.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from hydra.offensive_intel.context import OffensiveContext
from hydra.offensive_intel.effectiveness import CapabilityEffectivenessEngine
from hydra.offensive_intel.util import mean


class OffensiveCoverageAnalyzer:
    def __init__(self, ctx: Optional[OffensiveContext] = None,
                 engine: Optional[CapabilityEffectivenessEngine] = None):
        self.ctx = (ctx or OffensiveContext()).load()
        self.engine = engine or CapabilityEffectivenessEngine(self.ctx)

    def category_coverage(self) -> List[Dict]:
        cat = self.ctx.catalog()
        emap = self.engine.as_map()
        owner = self.ctx.owner_of()
        rows = []
        for category in sorted({c.category for c in cat.all()}):
            members = cat.by_category(category)
            n = len(members)
            effs = [emap[c.capability_id].effectiveness for c in members if c.capability_id in emap]
            verif = sum(1 for c in members if c.is_verification)
            exercised = sum(1 for c in members
                            if (o := self.ctx.capability_outcome(c.capability_id)) and o.events > 0)
            owned = sum(1 for c in members if owner.get(c.capability_id))
            rows.append({
                "category": category, "capabilities": n,
                "mean_effectiveness": round(mean(effs), 4),
                "verification_capable": verif,
                "verification_coverage_pct": round(100 * verif / n, 1) if n else 0.0,
                "exercised": exercised,
                "exercised_pct": round(100 * exercised / n, 1) if n else 0.0,
                "owned_by_agent": owned,
            })
        rows.sort(key=lambda d: (d["mean_effectiveness"], d["category"]))
        return rows

    def workflow_coverage(self) -> Dict:
        owner = self.ctx.owner_of()
        total = len(owner)
        owned = sum(1 for v in owner.values() if v)
        per_agent: Dict[str, int] = {}
        for v in owner.values():
            if v:
                per_agent[v] = per_agent.get(v, 0) + 1
        return {"total_capabilities": total, "owned_by_agent": owned,
                "orphan_capabilities": total - owned,
                "coverage_pct": round(100 * owned / total, 1) if total else 0.0,
                "capabilities_per_agent": dict(sorted(per_agent.items()))}

    def attack_path_coverage(self) -> Dict:
        exercised = {cid for cid, o in self.ctx.cap_outcomes.items() if o.events > 0}
        directed = [e for e in self.ctx.graph().edges()
                    if e["relation"] in ("requires", "enhances")]
        both = sum(1 for e in directed if e["from"] in exercised and e["to"] in exercised)
        return {"directed_edges": len(directed),
                "edges_both_endpoints_exercised": both,
                "path_coverage_pct": round(100 * both / len(directed), 1) if directed else 0.0,
                "exercised_capabilities": len(exercised)}

    def report(self) -> Dict:
        cov = self.category_coverage()
        return {"category_coverage": cov, "weakest_categories": cov[:5],
                "workflow_coverage": self.workflow_coverage(),
                "attack_path_coverage": self.attack_path_coverage(), "advisory": True}
