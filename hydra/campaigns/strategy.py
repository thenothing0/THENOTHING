"""
StrategyComparator (Phase Q) — compare two strategies on five metrics.

A strategy resolves to a capability set (a playbook id, else a capability category). Each is scored
on coverage / diversity / effectiveness / dependency-risk (reliance on bottleneck capabilities) /
redundancy (Phase-P overlap fully inside the set). Deterministic, advisory; O(C + D).
"""

from __future__ import annotations

from typing import Dict, List, Optional

from hydra.campaigns.campaign_model import CampaignContext
from hydra.campaigns.playbooks import PlaybookGenerator
from hydra.campaigns.util import DEPENDENCY_RISK_TOP, mean


class StrategyComparator:
    def __init__(self, cc: Optional[CampaignContext] = None):
        self.cc = cc or CampaignContext()
        self.pb = PlaybookGenerator(self.cc)

    def _resolve(self, name: str) -> List[str]:
        pb = self.pb.get(name)
        if pb:
            return [c["capability_id"] for c in pb["campaign_capabilities"]]
        return sorted(c.capability_id for c in self.cc.catalog().by_category(name))

    def _score(self, name: str, caps: List[str]) -> Dict:
        cat = self.cc.catalog()
        emap = self.cc.eff_map()
        capset = set(caps)
        cats = {cat.get(c).category for c in capset if cat.get(c)}
        effs = [emap[c].effectiveness for c in capset if c in emap]
        crit = {d["capability_id"] for d in self.cc.graph().critical_capabilities(top=DEPENDENCY_RISK_TOP)}
        dep_risk = round(len(capset & crit) / len(capset), 4) if capset else 0.0
        red = sum(1 for p in self.cc.redundant_pairs()
                  if p["capability_a"] in capset and p["capability_b"] in capset)
        return {"strategy": name, "coverage": len(capset),
                "diversity": round(len(cats) / len(capset), 4) if capset else 0.0,
                "effectiveness": round(mean(effs), 4) if effs else 0.0,
                "dependency_risk": dep_risk, "redundancy": red, "categories": sorted(cats)}

    def compare(self, strategy_a: str, strategy_b: str) -> Dict:
        a = self._score(strategy_a, self._resolve(strategy_a))
        b = self._score(strategy_b, self._resolve(strategy_b))
        better = {}
        for metric, higher_is_better in [("coverage", True), ("diversity", True),
                                         ("effectiveness", True), ("dependency_risk", False),
                                         ("redundancy", False)]:
            if a[metric] == b[metric]:
                better[metric] = "tie"
            elif (a[metric] > b[metric]) == higher_is_better:
                better[metric] = strategy_a
            else:
                better[metric] = strategy_b
        return {"strategy_a": a, "strategy_b": b, "better_per_metric": better, "advisory": True}
