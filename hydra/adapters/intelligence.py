"""
Adapter Intelligence, Capability Exercise Metrics & Runtime Analytics (Phase K).

Read-only analytics over the adapter registry + derived learning/health stores:

  * CapabilityExerciseAnalyzer — closes the Phase-J governance blind spot by measuring,
    per capability, whether it is declared / owned / has an adapter / has been exercised /
    has been verified, and rolling that up into coverage metrics.
  * AdapterIntelligence — healthiest/weakest adapters, failures, timeouts, summary.
  * RuntimeAnalytics — utilization, average runtime, timeout distribution, category
    coverage, execution-profile distribution.

Invariants: READ-ONLY. Never writes the wiki, never touches confidence.py / promotion.py,
never executes anything. Deterministic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from hydra.adapters.adapter_registry import AdapterRegistry
from hydra.adapters.tool_health import ToolHealthStore
from hydra.capabilities.capability_catalog import CapabilityCatalog
from hydra.capabilities.source_learning import SourceLearningStore
from hydra.knowledge.verification import VerificationLearningStore


# ── Capability exercise metrics ─────────────────────────────────────────────────
@dataclass
class CapabilityExerciseReport:
    total_capabilities: int = 0
    declared: int = 0
    owned: int = 0
    with_adapter: int = 0
    exercised: int = 0
    verified: int = 0
    per_capability: List[Dict] = field(default_factory=list)

    def _pct(self, n: int) -> float:
        return round(100 * n / self.total_capabilities, 1) if self.total_capabilities else 0.0

    def to_dict(self) -> Dict:
        return {
            "total_capabilities": self.total_capabilities,
            "declared": self.declared, "owned": self.owned,
            "with_adapter": self.with_adapter, "exercised": self.exercised,
            "verified": self.verified,
            "adapter_coverage_pct": self._pct(self.with_adapter),
            "exercise_coverage_pct": self._pct(self.exercised),
            "verification_coverage_pct": self._pct(self.verified),
            # utilization: of the capabilities that HAVE an adapter, how many are exercised
            "utilization_coverage_pct":
                round(100 * self.exercised / self.with_adapter, 1) if self.with_adapter else 0.0,
            "unexercised_capabilities":
                sorted(c["capability_id"] for c in self.per_capability if not c["exercised"]),
            "unverified_capabilities":
                sorted(c["capability_id"] for c in self.per_capability if not c["verified"]),
            "capabilities_without_adapter":
                sorted(c["capability_id"] for c in self.per_capability if not c["has_adapter"]),
        }


class CapabilityExerciseAnalyzer:
    def __init__(self, catalog: Optional[CapabilityCatalog] = None,
                 registry: Optional[AdapterRegistry] = None,
                 learning: Optional[SourceLearningStore] = None,
                 verification: Optional[VerificationLearningStore] = None,
                 health: Optional[ToolHealthStore] = None):
        self.catalog = (catalog or CapabilityCatalog()).load()
        self.registry = (registry or AdapterRegistry(catalog=self.catalog)).load()
        self.learning = learning or SourceLearningStore()
        self.verification = verification or VerificationLearningStore()
        self.health = health or ToolHealthStore()

    def report(self) -> CapabilityExerciseReport:
        # Pre-load derived signals once (single queries) → deterministic, O(events).
        src_events = {s.source_id[len("source."):]: s.total_events
                      for s in self.learning.all_scores() if s.source_id.startswith("source.")}
        ver_attempts = {m["method"]: m["attempts"] for m in self.verification.method_stats()}
        health_by_cap: Dict[str, Dict[str, int]] = {}
        for h in self.health.all_health():
            cap = h.adapter_id.split("::", 1)[0]
            agg = health_by_cap.setdefault(cap, {"events": 0, "validations": 0})
            agg["events"] += h.executions + h.validations + h.simulations
            agg["validations"] += h.validations

        rep = CapabilityExerciseReport()
        for cap in self.catalog.all():
            cid = cap.capability_id
            has_adapter = bool(self.registry.adapters_for_capability(cid))
            tool_events = sum(src_events.get(t, 0) + ver_attempts.get(t, 0) for t in cap.tools)
            hc = health_by_cap.get(cid, {"events": 0, "validations": 0})
            exercised = (tool_events > 0) or (hc["events"] > 0)
            verified = (hc["validations"] > 0) or (
                cap.is_verification and any(ver_attempts.get(t, 0) > 0 for t in cap.tools))
            owned = bool(cap.tools)
            rep.per_capability.append({
                "capability_id": cid, "category": cap.category,
                "declared": True, "owned": owned, "has_adapter": has_adapter,
                "exercised": exercised, "verified": verified,
            })
            rep.declared += 1
            rep.owned += 1 if owned else 0
            rep.with_adapter += 1 if has_adapter else 0
            rep.exercised += 1 if exercised else 0
            rep.verified += 1 if verified else 0
        rep.total_capabilities = rep.declared
        rep.per_capability.sort(key=lambda c: c["capability_id"])
        return rep


# ── Adapter intelligence ─────────────────────────────────────────────────────────
class AdapterIntelligence:
    def __init__(self, registry: Optional[AdapterRegistry] = None,
                 health: Optional[ToolHealthStore] = None):
        self.registry = (registry or AdapterRegistry()).load()
        self.health = health or ToolHealthStore()

    def _exercised(self) -> List:
        return [h for h in self.health.all_health() if h.total_outcomes > 0]

    def healthiest_adapters(self, n: int = 10) -> List[Dict]:
        ex = sorted(self._exercised(),
                    key=lambda h: (-h.reliability_score, -h.total_outcomes, h.adapter_id))
        return [h.to_dict() for h in ex[: max(1, n)]]

    def weakest_adapters(self, n: int = 10) -> List[Dict]:
        ex = sorted(self._exercised(),
                    key=lambda h: (h.reliability_score, -h.total_outcomes, h.adapter_id))
        return [h.to_dict() for h in ex[: max(1, n)]]

    def adapter_failures(self) -> List[Dict]:
        out = [h.to_dict() for h in self.health.all_health() if h.failures > 0]
        out.sort(key=lambda d: (-d["failures"], -d["failure_rate"], d["adapter_id"]))
        return out

    def adapter_timeouts(self) -> List[Dict]:
        out = [h.to_dict() for h in self.health.all_health() if h.timeout_count > 0]
        out.sort(key=lambda d: (-d["timeout_count"], -d["timeout_rate"], d["adapter_id"]))
        return out

    def adapter_summary(self) -> Dict:
        all_h = self.health.all_health()
        exercised = [h for h in all_h if h.total_outcomes > 0]
        total_adapters = self.registry.count()
        mean_reliability = (round(sum(h.reliability_score for h in exercised) / len(exercised), 4)
                            if exercised else 0.0)
        return {
            "total_adapters": total_adapters,
            "adapters_with_events": len(exercised),
            "utilization_pct": round(100 * len(exercised) / total_adapters, 1) if total_adapters else 0.0,
            "mean_reliability": mean_reliability,
            "total_executions": sum(h.executions for h in all_h),
            "total_validations": sum(h.validations for h in all_h),
            "total_simulations": sum(h.simulations for h in all_h),
            "total_successes": sum(h.successes for h in all_h),
            "total_failures": sum(h.failures for h in all_h),
            "total_timeouts": sum(h.timeout_count for h in all_h),
        }


# ── Runtime analytics ──────────────────────────────────────────────────────────
class RuntimeAnalytics:
    def __init__(self, registry: Optional[AdapterRegistry] = None,
                 health: Optional[ToolHealthStore] = None):
        self.registry = (registry or AdapterRegistry()).load()
        self.health = health or ToolHealthStore()

    def report(self, top: int = 10) -> Dict:
        all_h = self.health.all_health()
        exercised = [h for h in all_h if h.total_outcomes > 0]
        total_adapters = self.registry.count()

        utilization = sorted(
            ({"adapter_id": h.adapter_id,
              "events": h.executions + h.validations + h.simulations,
              "reliability_score": h.reliability_score} for h in exercised),
            key=lambda d: (-d["events"], d["adapter_id"]))[: max(1, top)]

        runtimes = [h.average_runtime for h in exercised if h.average_runtime > 0]
        avg_runtime = round(sum(runtimes) / len(runtimes), 4) if runtimes else 0.0

        cat_runtime = self.health.category_runtime()
        timeout_distribution = {c["category"]: c["timeouts"]
                                for c in cat_runtime if c["timeouts"] > 0}

        # category coverage: adapters present vs exercised, per category
        adapters_by_cat: Dict[str, int] = {}
        for a in self.registry.all_adapters():
            adapters_by_cat[a.category] = adapters_by_cat.get(a.category, 0) + 1
        exercised_by_cat: Dict[str, int] = {}
        for h in exercised:
            adef = self.registry.get_adapter(h.adapter_id)
            if adef:
                exercised_by_cat[adef.category] = exercised_by_cat.get(adef.category, 0) + 1
        category_coverage = {
            cat: {"adapters": n, "exercised": exercised_by_cat.get(cat, 0),
                  "coverage_pct": round(100 * exercised_by_cat.get(cat, 0) / n, 1) if n else 0.0}
            for cat, n in sorted(adapters_by_cat.items())}

        profile_distribution: Dict[str, int] = {}
        for a in self.registry.all_adapters():
            profile_distribution[a.execution_profile] = profile_distribution.get(a.execution_profile, 0) + 1

        return {
            "total_adapters": total_adapters,
            "adapters_with_events": len(exercised),
            "utilization": utilization,
            "average_runtime_ms": avg_runtime,
            "timeout_distribution": dict(sorted(timeout_distribution.items())),
            "category_coverage": category_coverage,
            "execution_profile_distribution": dict(sorted(profile_distribution.items())),
        }
