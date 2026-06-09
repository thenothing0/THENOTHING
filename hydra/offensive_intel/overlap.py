"""
OverlapAnalyzer (Phase P) — capability overlap / redundancy clusters.

Pairs are only compared WITHIN shared-finding-type buckets (bounded, not global O(C²)); overlap
blends finding-type and tool Jaccard. Redundant clusters are the connected components of the
redundant-pair graph. Deterministic, advisory only.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from hydra.offensive_intel.context import OffensiveContext
from hydra.offensive_intel.effectiveness import CapabilityEffectivenessEngine
from hydra.offensive_intel.util import REDUNDANCY_THRESHOLD, jaccard


class OverlapAnalyzer:
    def __init__(self, ctx: Optional[OffensiveContext] = None,
                 engine: Optional[CapabilityEffectivenessEngine] = None):
        self.ctx = (ctx or OffensiveContext()).load()
        self.engine = engine or CapabilityEffectivenessEngine(self.ctx)

    def redundant_pairs(self, threshold: float = REDUNDANCY_THRESHOLD,
                        limit: int = 50) -> List[Dict]:
        cat = self.ctx.catalog()
        buckets: Dict[str, List[str]] = {}
        for c in cat.all():
            for ft in c.supported_finding_types:
                buckets.setdefault(ft, []).append(c.capability_id)
        scored: Dict[tuple, float] = {}
        for members in buckets.values():
            uniq = sorted(set(members))
            for i in range(len(uniq)):
                for j in range(i + 1, len(uniq)):
                    a, b = uniq[i], uniq[j]
                    if (a, b) in scored:
                        continue
                    ca, cb = cat.get(a), cat.get(b)
                    score = round(0.7 * jaccard(ca.supported_finding_types, cb.supported_finding_types)
                                  + 0.3 * jaccard(ca.tools, cb.tools), 4)
                    if score >= threshold:
                        scored[(a, b)] = score
        emap = self.engine.as_map()
        rows = []
        for (a, b), s in scored.items():
            ea = emap.get(a).effectiveness if emap.get(a) else 0.0
            eb = emap.get(b).effectiveness if emap.get(b) else 0.0
            rows.append({"capability_a": a, "capability_b": b, "overlap": s,
                         "lower_value": a if ea <= eb else b, "advisory": True})
        rows.sort(key=lambda d: (-d["overlap"], d["capability_a"], d["capability_b"]))
        return rows[:max(1, limit)]

    def redundant_clusters(self, threshold: float = REDUNDANCY_THRESHOLD) -> List[Dict]:
        adj: Dict[str, set] = {}
        for p in self.redundant_pairs(threshold, limit=100000):
            adj.setdefault(p["capability_a"], set()).add(p["capability_b"])
            adj.setdefault(p["capability_b"], set()).add(p["capability_a"])
        seen, clusters = set(), []
        for node in sorted(adj):
            if node in seen:
                continue
            stack, comp = [node], set()
            while stack:
                n = stack.pop()
                if n in comp:
                    continue
                comp.add(n)
                seen.add(n)
                stack.extend(adj[n] - comp)
            if len(comp) > 1:
                clusters.append(sorted(comp))
        clusters.sort(key=lambda c: (-len(c), c[0]))
        return [{"capabilities": c, "size": len(c), "advisory": True} for c in clusters]

    def report(self, limit: int = 25) -> Dict:
        pairs = self.redundant_pairs(limit=limit)
        clusters = self.redundant_clusters()
        return {"redundant_pairs": pairs, "redundant_pair_count": len(pairs),
                "redundant_clusters": clusters, "cluster_count": len(clusters),
                "advisory": True}
