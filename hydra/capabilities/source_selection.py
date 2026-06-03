"""
AdaptiveSourceSelector (Phase E) — learning-driven, advisory source ranking.

Ranks a capability's recon sources using the Phase-D learning signals
(trust / effectiveness / novelty) plus **recency decay** and an **exploration
bonus**, blended with each source's declared static prior (`confidence_weight`) so
cold-start sources still order sensibly.

Invariants (unchanged): this layer is READ-ONLY over the derived learning store and
the capability registry. It NEVER touches confidence.py, promotion.py, or the wiki,
and it produces only an **advisory** ranking. Deterministic given a fixed `now`.

Scaling: selection is O(sources_in_capability) — a bounded set (~tens), each a single
indexed learning query. It is independent of the number of findings/evidence pages,
and is further capped by `SelectionPolicy.max_sources` + a wall-clock timeout.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from hydra.capabilities.registry import CapabilityRegistry
from hydra.capabilities.source_learning import (
    SourceLearningStore,
    exploration_bonus,
    recency_factor,
)
from hydra.capabilities.sources import ExecutionPolicy, Source

# Declared selection weights (advisory ranking config; NOT confidence logic). Sum 1.0.
SELECTION_WEIGHTS = {
    "trust": 0.30,
    "effectiveness": 0.25,   # decayed by recency
    "novelty": 0.15,
    "exploration": 0.15,
    "prior": 0.15,           # the source's declared static confidence_weight
}


@dataclass
class SourceSelectionScore:
    source_id: str
    name: str
    category: str
    score: float
    runnable: bool
    components: Dict[str, float] = field(default_factory=dict)
    total_events: int = 0

    def to_dict(self) -> Dict:
        return {"source_id": self.source_id, "name": self.name, "category": self.category,
                "score": self.score, "runnable": self.runnable,
                "components": self.components, "total_events": self.total_events}


@dataclass
class SelectionPolicy:
    """Operational guardrails for selection (deterministic caps + timeout)."""
    max_sources: int = 25
    timeout_seconds: float = 5.0


class AdaptiveSourceSelector:
    def __init__(self, registry: Optional[CapabilityRegistry] = None,
                 learning: Optional[SourceLearningStore] = None,
                 now: Optional[float] = None):
        self.registry = (registry or CapabilityRegistry()).load()
        self.learning = learning or SourceLearningStore()
        self.now = now if now is not None else time.time()

    def score_source(self, source: Source, runnable: bool = True) -> SourceSelectionScore:
        sc = self.learning.scores(source.id)
        components = {
            "trust": round(sc.trust_score, 4),
            "effectiveness": round(sc.effectiveness_score
                                   * recency_factor(sc.last_success_at, self.now), 4),
            "novelty": round(sc.novelty_score, 4),
            "exploration": exploration_bonus(sc.total_events),
            "prior": round(min(1.0, max(0.0, source.confidence_weight)), 4),
        }
        total = round(sum(SELECTION_WEIGHTS[k] * v for k, v in components.items()), 4)
        return SourceSelectionScore(
            source_id=source.id, name=source.name, category=source.category.value,
            score=total, runnable=runnable, components=components,
            total_events=sc.total_events,
        )

    def select(self, capability: str, exec_policy: Optional[ExecutionPolicy] = None,
               limit: int = 10, policy: Optional[SelectionPolicy] = None) -> List[SourceSelectionScore]:
        """Ranked, runnable-under-policy sources for a capability (advisory).

        Deterministic: score desc, then source_id asc. Bounded by `max_sources` and a
        timeout; `limit` truncates the returned head."""
        policy = policy or SelectionPolicy()
        exec_policy = exec_policy or ExecutionPolicy.offline()
        cap = self.registry.get(capability)
        if not cap:
            raise KeyError(f"unknown capability: {capability}")

        runnable_ids = {s.id for s in cap.runnable_sources(exec_policy)}
        start = time.perf_counter()
        scored: List[SourceSelectionScore] = []
        for src in cap.sources[: policy.max_sources]:
            if policy.timeout_seconds and (time.perf_counter() - start) > policy.timeout_seconds:
                break
            scored.append(self.score_source(src, runnable=src.id in runnable_ids))

        scored.sort(key=lambda s: (-s.score, s.source_id))
        return scored[: max(1, limit)]
