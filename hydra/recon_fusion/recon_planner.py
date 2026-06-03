"""
ReconPlanner (Phase E) — advisory, learning-driven reconnaissance planning.

Given a target, its type, the count of prior findings, and the derived source
scores, it produces an **ordered recon plan**: which capabilities to run, the
learning-ranked sources for each, an expected-value estimate, and an
opportunity-driven emphasis (which signatures deserve more evidence, whether the
target is under-covered).

Invariants (unchanged): **advisory only** — it recommends, it never executes recon,
never confirms findings, never writes the wiki, and never touches confidence.py or
promotion.py. Deterministic given a fixed `now`. Bounded: it iterates a small,
capped set of capabilities × sources — O(1) in the number of findings/evidence pages.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from hydra.capabilities.registry import CapabilityRegistry
from hydra.capabilities.source_learning import SourceLearningStore
from hydra.capabilities.source_selection import (
    AdaptiveSourceSelector,
    SourceSelectionScore,
)
from hydra.capabilities.sources import ExecutionPolicy

# target type → ordered capabilities (priority high→low). Bounded per type.
TARGET_TYPE_CAPABILITIES: Dict[str, List[str]] = {
    "web": ["discover_subdomains", "http_probe", "discover_urls", "technology_fingerprinting"],
    "api": ["discover_subdomains", "http_probe", "discover_urls", "dns_intelligence",
            "technology_fingerprinting"],
    "cloud": ["cloud_asset_discovery", "discover_subdomains", "asn_intelligence", "dns_intelligence"],
    "network": ["asn_intelligence", "dns_intelligence", "discover_subdomains"],
    "code": ["repository_intelligence", "discover_subdomains"],
    "default": ["discover_subdomains", "http_probe", "dns_intelligence"],
}
# Below this many prior findings the target is treated as under-covered (favor breadth).
_UNDER_COVERED_THRESHOLD = 5


@dataclass
class ReconStep:
    order: int
    capability: str
    sources: List[SourceSelectionScore]
    expected_value: float
    rationale: str

    def to_dict(self) -> Dict:
        return {"order": self.order, "capability": self.capability,
                "expected_value": self.expected_value, "rationale": self.rationale,
                "sources": [s.to_dict() for s in self.sources]}


@dataclass
class ReconPlan:
    target: str
    target_type: str
    expected_value: float
    steps: List[ReconStep] = field(default_factory=list)
    ranked_sources: List[SourceSelectionScore] = field(default_factory=list)
    emphasis: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "target": self.target, "target_type": self.target_type,
            "expected_value": self.expected_value,
            "steps": [s.to_dict() for s in self.steps],
            "ranked_sources": [s.to_dict() for s in self.ranked_sources],
            "emphasis": self.emphasis,
        }


@dataclass
class PlannerLimits:
    max_capabilities: int = 8
    sources_per_step: int = 5
    timeout_seconds: float = 10.0


class ReconPlanner:
    def __init__(self, registry: Optional[CapabilityRegistry] = None,
                 learning: Optional[SourceLearningStore] = None,
                 now: Optional[float] = None):
        self.registry = (registry or CapabilityRegistry()).load()
        self.learning = learning or SourceLearningStore()
        self.selector = AdaptiveSourceSelector(self.registry, self.learning, now=now)

    def plan(self, target: str, target_type: str = "web", prior_findings: int = 0,
             exec_policy: Optional[ExecutionPolicy] = None,
             limits: Optional[PlannerLimits] = None) -> ReconPlan:
        limits = limits or PlannerLimits()
        exec_policy = exec_policy or ExecutionPolicy.offline()
        caps = TARGET_TYPE_CAPABILITIES.get(target_type, TARGET_TYPE_CAPABILITIES["default"])
        caps = [c for c in caps if self.registry.get(c)][: limits.max_capabilities]

        start = time.perf_counter()
        steps: List[ReconStep] = []
        for i, cap in enumerate(caps):
            if limits.timeout_seconds and (time.perf_counter() - start) > limits.timeout_seconds:
                break
            sources = self.selector.select(cap, exec_policy, limit=limits.sources_per_step)
            runnable = [s for s in sources if s.runnable] or sources
            ev = round(sum(s.score for s in runnable) / len(runnable), 4) if runnable else 0.0
            steps.append(ReconStep(
                order=i, capability=cap, sources=sources, expected_value=ev,
                rationale=f"{cap}: top source '{sources[0].name}' "
                          f"(score {sources[0].score})" if sources else f"{cap}: no sources",
            ))

        # Order-weighted overall expected value (earlier steps weigh more). In [0,1].
        wsum = sum(1.0 / (i + 1) for i in range(len(steps)))
        overall = round(sum(s.expected_value / (i + 1) for i, s in enumerate(steps)) / wsum, 4) \
            if steps else 0.0

        # Flat ranked source list across the plan (dedup by id, best score wins).
        best: Dict[str, SourceSelectionScore] = {}
        for st in steps:
            for s in st.sources:
                if s.source_id not in best or s.score > best[s.source_id].score:
                    best[s.source_id] = s
        ranked = sorted(best.values(), key=lambda s: (-s.score, s.source_id))

        return ReconPlan(
            target=target, target_type=target_type, expected_value=overall,
            steps=steps, ranked_sources=ranked,
            emphasis=self._emphasis(prior_findings),
        )

    def _emphasis(self, prior_findings: int) -> Dict:
        """Opportunity-driven, read-only guidance (advisory). Derived from learning."""
        promising = [p for p in self.learning.successful_patterns()
                     if p["acceptance_rate"] >= 0.5][:5]
        return {
            "target_under_covered": prior_findings < _UNDER_COVERED_THRESHOLD,
            "prior_findings": prior_findings,
            "promising_signatures": promising,  # high-acceptance signatures worth more evidence
            "note": ("favor breadth — target under-covered"
                     if prior_findings < _UNDER_COVERED_THRESHOLD
                     else "favor depth on promising signatures"),
        }
