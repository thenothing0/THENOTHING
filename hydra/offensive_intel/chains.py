"""
AttackChainIntelligence (Phase P) — chain popularity / effectiveness / diversity.

Builds candidate attack chains by traversing the capability dependency graph in EXECUTION order
(prerequisite → dependent). A `requires` edge {from:A, to:B} means "A requires B", so B precedes A
→ the forward (execution) edge is B→A. Bounded DFS (depth-cap + fan-out-cap + a hard chain cap)
guarantees termination. Advisory only — it scores the capability MODEL and never runs a chain.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Optional

from hydra.offensive_intel.context import OffensiveContext
from hydra.offensive_intel.effectiveness import CapabilityEffectivenessEngine
from hydra.offensive_intel.util import mean, norm

MAX_DEPTH = 6
FAN_OUT = 4
MAX_CHAINS = 200


class AttackChainIntelligence:
    def __init__(self, ctx: Optional[OffensiveContext] = None,
                 engine: Optional[CapabilityEffectivenessEngine] = None,
                 max_depth: int = MAX_DEPTH, fan_out: int = FAN_OUT):
        self.ctx = (ctx or OffensiveContext()).load()
        self.engine = engine or CapabilityEffectivenessEngine(self.ctx)
        self.max_depth = max_depth
        self.fan_out = fan_out
        self._chains: Optional[List[Dict]] = None

    def _build(self) -> List[Dict]:
        if self._chains is not None:
            return self._chains
        cat = self.ctx.catalog()
        emap = self.engine.as_map()

        def eff(cid: str) -> float:
            e = emap.get(cid)
            return e.effectiveness if e else 0.0

        fwd: Dict[str, List[str]] = defaultdict(list)
        req_from, req_to, deg = set(), set(), {}
        for e in self.ctx.graph().edges():
            if e["relation"] == "requires":
                fwd[e["to"]].append(e["from"])      # prerequisite(to) → dependent(from)
                req_from.add(e["from"])
                req_to.add(e["to"])
            if e["relation"] in ("requires", "enhances"):
                deg[e["from"]] = deg.get(e["from"], 0) + 1
                deg[e["to"]] = deg.get(e["to"], 0) + 1
        max_degree = max(deg.values(), default=1) or 1
        # follow only the top-FAN_OUT most-effective successors (deterministic order)
        for k in list(fwd):
            fwd[k] = sorted(set(fwd[k]), key=lambda x: (-eff(x), x))[: self.fan_out]
        seeds = sorted(req_to - req_from)           # recon roots that have dependents
        chains: List[List[str]] = []

        def dfs(path: List[str]) -> None:
            if len(chains) >= MAX_CHAINS:
                return
            nxts = [n for n in fwd.get(path[-1], []) if n not in path]
            if not nxts or len(path) >= self.max_depth:
                if len(path) >= 2:
                    chains.append(list(path))
                return
            for n in nxts:
                if len(chains) >= MAX_CHAINS:
                    break
                dfs(path + [n])

        for s in seeds:
            dfs([s])

        rows = []
        for ch in chains:
            terminal = cat.get(ch[-1])
            verify_bonus = 1.1 if (terminal and terminal.is_verification) else 1.0
            cats = sorted({cat.get(c).category for c in ch if cat.get(c)})
            rows.append({
                "chain": ch, "length": len(ch),
                "effectiveness": round(min(1.0, mean([eff(c) for c in ch]) * verify_bonus), 4),
                "diversity": round(len(cats) / len(ch), 4),
                "popularity": round(mean([norm(deg.get(c, 0), max_degree) for c in ch]), 4),
                "categories": cats,
                "terminal_verification": bool(terminal and terminal.is_verification),
                "advisory": True,
            })
        uniq = {tuple(r["chain"]): r for r in rows}
        self._chains = sorted(uniq.values(),
                              key=lambda r: (-r["effectiveness"], -r["diversity"], r["chain"]))
        return self._chains

    def chains(self, target_type: str = "", limit: int = 10) -> Dict:
        ranked = self._build()
        if target_type:
            cat = self.ctx.catalog()
            ranked = [r for r in ranked
                      if (c := cat.get(r["chain"][0])) and target_type in c.supported_target_types]
        return {"chains": ranked[:max(1, limit)], "total_chains": len(self._build()),
                "target_type": target_type or "any",
                "bounds": {"max_depth": self.max_depth, "fan_out": self.fan_out,
                           "max_chains": MAX_CHAINS}, "advisory": True}

    def report(self, limit: int = 10) -> Dict:
        return self.chains(limit=limit)
