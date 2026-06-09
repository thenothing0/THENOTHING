"""
OffensiveGapAnalyzer (Phase P) — missing capabilities / weak categories / weak chains.

Weak categories come from coverage; missing finding-types are those whose best supporting
capability is weak (plus dependency-graph endpoints absent from the catalog); weak chains have a
low-effectiveness link or no verifying terminal. Deterministic, advisory only.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from hydra.offensive_intel.chains import AttackChainIntelligence
from hydra.offensive_intel.context import OffensiveContext
from hydra.offensive_intel.coverage import OffensiveCoverageAnalyzer
from hydra.offensive_intel.effectiveness import CapabilityEffectivenessEngine
from hydra.offensive_intel.util import WEAK_EFFECTIVENESS


class OffensiveGapAnalyzer:
    def __init__(self, ctx: Optional[OffensiveContext] = None,
                 engine: Optional[CapabilityEffectivenessEngine] = None):
        self.ctx = (ctx or OffensiveContext()).load()
        self.engine = engine or CapabilityEffectivenessEngine(self.ctx)
        self.coverage = OffensiveCoverageAnalyzer(self.ctx, self.engine)
        self.attack_chains = AttackChainIntelligence(self.ctx, self.engine)

    def weak_categories(self, threshold: float = WEAK_EFFECTIVENESS) -> List[Dict]:
        return [c for c in self.coverage.category_coverage()
                if c["mean_effectiveness"] < threshold or c["verification_coverage_pct"] == 0.0]

    def missing_finding_types(self) -> List[Dict]:
        cat = self.ctx.catalog()
        emap = self.engine.as_map()
        ft_caps: Dict[str, List[str]] = {}
        for c in cat.all():
            for ft in c.supported_finding_types:
                ft_caps.setdefault(ft, []).append(c.capability_id)
        weak = []
        for ft in sorted(ft_caps):
            effs = [emap[cid].effectiveness for cid in ft_caps[ft] if cid in emap]
            best = max(effs, default=0.0)
            if best < WEAK_EFFECTIVENESS:
                weak.append({"finding_type": ft, "capabilities": sorted(ft_caps[ft]),
                             "best_effectiveness": round(best, 4), "reason": "all capabilities weak",
                             "advisory": True})
        weak.sort(key=lambda d: (d["best_effectiveness"], d["finding_type"]))
        structural = [{"finding_type": cid, "capabilities": [], "best_effectiveness": 0.0,
                       "reason": "referenced in dependency graph but absent from catalog",
                       "advisory": True}
                      for cid in self.ctx.graph().coverage_gaps()]
        return weak + structural

    def weak_chains(self, threshold: float = WEAK_EFFECTIVENESS, limit: int = 25) -> List[Dict]:
        emap = self.engine.as_map()
        out = []
        for ch in self.attack_chains.chains(limit=100000)["chains"]:
            link_effs = [emap[c].effectiveness for c in ch["chain"] if c in emap]
            weakest = min(link_effs, default=0.0)
            if weakest < threshold or not ch["terminal_verification"]:
                out.append({"chain": ch["chain"], "weakest_link_effectiveness": round(weakest, 4),
                            "terminal_verification": ch["terminal_verification"], "advisory": True})
        out.sort(key=lambda d: (d["weakest_link_effectiveness"], d["chain"]))
        return out[:max(1, limit)]

    def report(self) -> Dict:
        wc = self.weak_categories()
        mft = self.missing_finding_types()
        wch = self.weak_chains()
        return {"weak_categories": wc, "weak_category_count": len(wc),
                "missing_finding_types": mft, "missing_finding_type_count": len(mft),
                "weak_chains": wch, "weak_chain_count": len(wch), "advisory": True}
