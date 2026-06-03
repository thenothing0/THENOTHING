"""
ToolSelector + CapabilityCoverage (Phase G) — learning-driven tool orchestration.

Given a capability, rank its interchangeable tools using accumulated learning:
recon effectiveness (recency-decayed) + verification effectiveness + exploration +
trust + the capability's static prior. Deterministic given a fixed `now`.

CapabilityCoverage gives read-only orchestration analysis: uncovered capabilities,
weak categories, over-used and under-explored tools.

Invariants: READ-ONLY over the derived learning stores + the catalog. Never writes the
wiki, never touches confidence.py / promotion.py, never executes a tool. Scales by
loading each learning store once (single query) and operating over bounded tool lists.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from hydra.capabilities.capability_catalog import CapabilityCatalog
from hydra.capabilities.source_learning import (
    SourceLearningStore,
    exploration_bonus,
    recency_factor,
)
from hydra.knowledge.verification import VerificationLearningStore

# Declared tool-selection weights (advisory; NOT confidence logic). Sum 1.0.
TOOL_SELECTION_WEIGHTS = {
    "effectiveness": 0.30,   # recon yield, recency-decayed
    "verification": 0.20,    # verification success rate (if a verifier)
    "exploration": 0.20,     # anti-monopoly bonus for under-used tools
    "trust": 0.15,
    "prior": 0.15,           # the capability's declared confidence_weight
}


@dataclass
class ToolScore:
    tool: str
    capability_id: str
    score: float
    total_events: int
    components: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {"tool": self.tool, "capability_id": self.capability_id,
                "score": self.score, "total_events": self.total_events,
                "components": self.components}


class ToolSelector:
    def __init__(self, catalog: Optional[CapabilityCatalog] = None,
                 learning: Optional[SourceLearningStore] = None,
                 verification: Optional[VerificationLearningStore] = None,
                 now: Optional[float] = None):
        self.catalog = (catalog or CapabilityCatalog()).load()
        self.learning = learning or SourceLearningStore()
        self.verification = verification or VerificationLearningStore()
        self.now = now if now is not None else time.time()

    # Load each store once → {key: stats} maps (no per-tool N+1 queries).
    def _maps(self):
        src = {s.source_id: s for s in self.learning.all_scores()}
        ver = {m["method"]: m for m in self.verification.method_stats()}
        return src, ver

    def _score_tool(self, tool: str, cap, src_map, ver_map) -> ToolScore:
        s = src_map.get(f"source.{tool}")
        vm = ver_map.get(tool)
        recon_events = s.total_events if s else 0
        ver_events = vm["attempts"] if vm else 0
        eff = (s.effectiveness_score * recency_factor(s.last_success_at, self.now)) if s else 0.0
        components = {
            "effectiveness": round(eff, 4),
            "verification": round(vm["success_rate"], 4) if vm else 0.5,
            "exploration": exploration_bonus(recon_events + ver_events),
            "trust": round(s.trust_score, 4) if s else 0.5,
            "prior": round(min(1.0, max(0.0, cap.confidence_weight)), 4),
        }
        total = round(sum(TOOL_SELECTION_WEIGHTS[k] * v for k, v in components.items()), 4)
        return ToolScore(tool=tool, capability_id=cap.capability_id, score=total,
                         total_events=recon_events + ver_events, components=components)

    def rank(self, capability_id: str, limit: int = 10) -> List[ToolScore]:
        cap = self.catalog.get(capability_id)
        if cap is None:
            raise KeyError(f"unknown capability: {capability_id}")
        src_map, ver_map = self._maps()
        scored = [self._score_tool(t, cap, src_map, ver_map) for t in cap.tools]
        scored.sort(key=lambda t: (-t.score, t.tool))   # deterministic
        return scored[: max(1, limit)]

    def select(self, capability_id: str) -> Optional[ToolScore]:
        ranked = self.rank(capability_id, limit=1)
        return ranked[0] if ranked else None


class CapabilityCoverage:
    """Read-only orchestration coverage analysis from the catalog + learning stores."""

    def __init__(self, catalog: Optional[CapabilityCatalog] = None,
                 learning: Optional[SourceLearningStore] = None,
                 verification: Optional[VerificationLearningStore] = None):
        self.catalog = (catalog or CapabilityCatalog()).load()
        self.learning = learning or SourceLearningStore()
        self.verification = verification or VerificationLearningStore()

    def _tool_events(self) -> Dict[str, int]:
        """Total learning events per tool (recon source events + verification attempts)."""
        events: Dict[str, int] = {}
        for s in self.learning.all_scores():
            if s.source_id.startswith("source."):
                events[s.source_id[len("source."):]] = events.get(s.source_id[7:], 0) + s.total_events
        for m in self.verification.method_stats():
            events[m["method"]] = events.get(m["method"], 0) + m["attempts"]
        return events

    def report(self, overused_top: int = 10) -> Dict:
        events = self._tool_events()

        def cap_events(cap) -> int:
            return sum(events.get(t, 0) for t in cap.tools)

        caps = self.catalog.all()
        uncovered = sorted(c.capability_id for c in caps if cap_events(c) == 0)

        # weak areas: per category, mean capability event coverage (ascending = weakest).
        by_cat: Dict[str, List[int]] = {}
        for c in caps:
            by_cat.setdefault(c.category, []).append(cap_events(c))
        weak = sorted(({"category": cat, "mean_events": round(sum(v) / len(v), 2),
                        "uncovered": sum(1 for x in v if x == 0)}
                       for cat, v in by_cat.items()),
                      key=lambda d: (d["mean_events"], d["category"]))

        all_tools = self.catalog.all_tools()
        used = [(t, events.get(t, 0)) for t in all_tools]
        overused = sorted(used, key=lambda x: (-x[1], x[0]))[:overused_top]
        underexplored = sorted(t for t, n in used if n == 0)

        return {
            "total_capabilities": len(caps),
            "uncovered_capabilities": uncovered,
            "uncovered_count": len(uncovered),
            "weak_capability_areas": weak,
            "overused_tools": [{"tool": t, "events": n} for t, n in overused if n > 0],
            "underexplored_tools": underexplored,
            "underexplored_count": len(underexplored),
        }
