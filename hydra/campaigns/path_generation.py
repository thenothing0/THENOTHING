"""
PathGeneration (Phase Q) — capability sequencing.

Two deterministic, bounded views: (1) `sequence` orders a capability set into execution order by
requires-depth (prerequisites first) then effectiveness; (2) `generate` reuses the Phase-P bounded
AttackChainIntelligence. O(C + D); no quadratic scans. Advisory, NON-executing.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from hydra.campaigns.campaign_model import CampaignContext


class PathGeneration:
    def __init__(self, cc: Optional[CampaignContext] = None):
        self.cc = cc or CampaignContext()

    def sequence(self, capabilities) -> List[str]:
        capset = set(capabilities)
        emap = self.cc.eff_map()
        graph = self.cc.graph()
        depth_cache: Dict[str, int] = {}

        def depth(cid: str, seen: frozenset) -> int:
            if cid in depth_cache:
                return depth_cache[cid]
            if cid in seen:
                return 0
            reqs = [r for r in graph.neighbors(cid, "requires") if r in capset]
            d = 0 if not reqs else 1 + max(depth(r, seen | {cid}) for r in reqs)
            depth_cache[cid] = d
            return d

        return sorted(capset, key=lambda c: (depth(c, frozenset()),
                                             -(emap[c].effectiveness if c in emap else 0.0), c))

    def generate(self, target_type: str = "", limit: int = 10) -> Dict:
        out = self.cc.oi.attack.chains(target_type=target_type, limit=limit)
        return {"chains": out["chains"], "total_chains": out["total_chains"],
                "bounds": out["bounds"], "target_type": target_type or "any", "advisory": True}
