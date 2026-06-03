"""
AdapterSelector (Phase K) — learning-driven, deterministic, advisory adapter ranking.

Given a capability, rank its adapters using accumulated learning: source-learning
effectiveness (recency-decayed), verification success, tool-health reliability, the
capability's static prior, an anti-monopoly exploration bonus, and a recency factor.

Invariants: READ-ONLY over the derived learning/health stores + the catalog/registry.
Never writes the wiki, never touches confidence.py / promotion.py, NEVER executes an
adapter. Deterministic given a fixed `now`. Advisory only.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from hydra.adapters.adapter_registry import AdapterRegistry
from hydra.adapters.tool_health import ToolHealthStore
from hydra.capabilities.source_learning import (
    SourceLearningStore,
    exploration_bonus,
    recency_factor,
)
from hydra.knowledge.verification import VerificationLearningStore

# Declared adapter-selection weights (advisory; NOT confidence logic). Sum 1.0.
ADAPTER_SELECTION_WEIGHTS = {
    "effectiveness": 0.25,   # recon yield, recency-decayed
    "reliability": 0.25,     # tool-health success reputation
    "verification": 0.15,    # verification success rate (if a verifier)
    "trust": 0.10,
    "exploration": 0.15,     # anti-monopoly bonus for under-used adapters
    "prior": 0.10,           # capability's declared confidence_weight
}


@dataclass
class AdapterScore:
    adapter_id: str
    capability_id: str
    tool_name: str
    score: float
    total_events: int
    components: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {"adapter_id": self.adapter_id, "capability_id": self.capability_id,
                "tool_name": self.tool_name, "score": self.score,
                "total_events": self.total_events, "components": self.components}


class AdapterSelector:
    def __init__(self, registry: Optional[AdapterRegistry] = None,
                 learning: Optional[SourceLearningStore] = None,
                 verification: Optional[VerificationLearningStore] = None,
                 health: Optional[ToolHealthStore] = None,
                 now: Optional[float] = None):
        self.registry = (registry or AdapterRegistry()).load()
        self.learning = learning or SourceLearningStore()
        self.verification = verification or VerificationLearningStore()
        self.health = health or ToolHealthStore()
        self.now = now if now is not None else time.time()
        self._cached_maps = None

    def _maps(self):
        # Load each store once → cached per instance (so ranking many capabilities does
        # not re-scan). Read-only for the selector's lifetime.
        if self._cached_maps is None:
            src = {s.source_id: s for s in self.learning.all_scores()}
            ver = {m["method"]: m for m in self.verification.method_stats()}
            hlt = {h.adapter_id: h for h in self.health.all_health()}
            self._cached_maps = (src, ver, hlt)
        return self._cached_maps

    def _score(self, adapter, src_map, ver_map, hlt_map) -> AdapterScore:
        s = src_map.get(f"source.{adapter.tool_name}")
        vm = ver_map.get(adapter.tool_name)
        h = hlt_map.get(adapter.adapter_id)
        recon_events = s.total_events if s else 0
        ver_events = vm["attempts"] if vm else 0
        health_events = h.total_outcomes if h else 0
        eff = (s.effectiveness_score * recency_factor(s.last_success_at, self.now)) if s else 0.0
        # reliability: tool-health reputation, recency-decayed toward neutral when stale.
        reliability = (h.reliability_score * recency_factor(h.last_success_at, self.now)) if h else 0.5
        components = {
            "effectiveness": round(eff, 4),
            "reliability": round(reliability, 4),
            "verification": round(vm["success_rate"], 4) if vm else 0.5,
            "trust": round(s.trust_score, 4) if s else 0.5,
            "exploration": exploration_bonus(recon_events + ver_events + health_events),
            "prior": round(min(1.0, max(0.0, adapter.confidence_weight)), 4),
        }
        total = round(sum(ADAPTER_SELECTION_WEIGHTS[k] * v for k, v in components.items()), 4)
        return AdapterScore(adapter_id=adapter.adapter_id, capability_id=adapter.capability_id,
                            tool_name=adapter.tool_name, score=total,
                            total_events=recon_events + ver_events + health_events,
                            components=components)

    def rank(self, capability_id: str, limit: int = 10) -> List[AdapterScore]:
        adapters = self.registry.adapters_for_capability(capability_id)
        if not adapters:
            raise KeyError(f"no adapters for capability: {capability_id}")
        src_map, ver_map, hlt_map = self._maps()
        scored = [self._score(a, src_map, ver_map, hlt_map) for a in adapters]
        scored.sort(key=lambda x: (-x.score, x.adapter_id))   # deterministic
        return scored[: max(1, limit)]

    def select(self, capability_id: str) -> Optional[AdapterScore]:
        ranked = self.rank(capability_id, limit=1)
        return ranked[0] if ranked else None
