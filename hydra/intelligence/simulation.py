"""
Autonomous Knowledge Simulation & Decision Intelligence (Phase L).

A fully DERIVED, deterministic, ADVISORY simulation layer that PREDICTS the likely outcome
of proposed workflows / agent plans / capability selections / source choices / verification
playbooks / adapter strategies BEFORE execution — using only the historical learning stores
(source learning, verification learning, adapter health, runtime history) + the catalogs.

Hard invariants (unchanged): NO execution, exploitation, confirmation, promotion, confidence
updates, or wiki mutation. promotion.py / confidence.py are untouched. All state is derived/
disposable under `data/` (rebuildable). Deterministic given injected `now`. Offline-first.

Performance: a single shared SimulationContext pre-loads every learning store ONCE (single
grouped queries, O(E)); all simulators operate over bounded capability/adapter lists and
memoize per-capability impact, so 10k simulations are O(10k × caps), not O(E) per call.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from hydra.adapters.adapter_registry import AdapterRegistry
from hydra.adapters.tool_health import ToolHealthStore
from hydra.agents.planner import (
    TARGET_TYPE_CATEGORIES,
    AgentIntelligence,
    AgentPlan,
    AgentPlanner,
)
from hydra.capabilities.capability_catalog import CapabilityCatalog
from hydra.capabilities.source_learning import SourceLearningStore, recency_factor
from hydra.knowledge.verification import VerificationLearningStore

_DEFAULT_DB = Path(__file__).resolve().parents[2] / "data" / "decision_learning.db"

# Categories whose findings tend to compose into multi-step chains (structural prior).
CHAIN_PRONE = {"web", "api", "cloud", "verification", "infrastructure"}

# Declared capability expected-value weights (advisory; NOT confidence logic). Sum 1.0.
IMPACT_WEIGHTS = {
    "findings": 0.30, "verification": 0.20, "reliability": 0.20,
    "chain": 0.15, "pattern": 0.15,
}

# Strategy definitions: scoring emphasis over the per-capability impact metrics.
STRATEGIES = {
    "aggressive_coverage": {"findings": 0.6, "verification": 0.1, "reliability": 0.1,
                            "chain": 0.1, "pattern": 0.1},
    "balanced_coverage": dict(IMPACT_WEIGHTS),
    "verification_first": {"findings": 0.15, "verification": 0.5, "reliability": 0.2,
                           "chain": 0.075, "pattern": 0.075},
}


def _mean(xs: List[float]) -> float:
    xs = [x for x in xs if x is not None]
    return sum(xs) / len(xs) if xs else 0.0


def _or_prob(ps: List[float]) -> float:
    """Probabilistic OR: 1 - Π(1 - p). Probability ≥1 of the events occurs."""
    acc = 1.0
    for p in ps:
        acc *= (1.0 - max(0.0, min(1.0, p)))
    return round(1.0 - acc, 4)


def _band(value: float) -> str:
    return "high" if value >= 0.66 else "medium" if value >= 0.33 else "low"


# ── shared context (load every store ONCE) ──────────────────────────────────────
class SimulationContext:
    def __init__(self, catalog=None, registry=None, learning=None, verification=None,
                 health=None, now: Optional[float] = None):
        self.now = now if now is not None else time.time()
        self.catalog: CapabilityCatalog = (catalog or CapabilityCatalog()).load()
        self.registry: AdapterRegistry = (registry or AdapterRegistry(catalog=self.catalog)).load()
        learning = learning or SourceLearningStore()
        verification = verification or VerificationLearningStore()
        health = health or ToolHealthStore()

        self.src = {s.source_id: s for s in learning.all_scores()}           # source.<tool> → scores
        self.ver = {m["method"]: m for m in verification.method_stats()}     # tool → method stats
        self.health_by_cap: Dict[str, list] = {}
        for h in health.all_health():
            self.health_by_cap.setdefault(h.adapter_id.split("::", 1)[0], []).append(h)

        # historical workflow completion rate (advisory prior; guarded).
        self.hist_completion = 0.7
        try:
            from hydra.runtime.engine import RuntimeIntelligence
            wf = RuntimeIntelligence().report().get("workflow_summary", {})
            done, failed = wf.get("completed", 0), wf.get("failed", 0)
            if done + failed > 0:
                self.hist_completion = round(done / (done + failed), 4)
        except Exception:
            pass

        # distinct finding-types / categories in the catalog (diversity normalizers).
        self._all_finding_types = {ft for c in self.catalog.all() for ft in c.supported_finding_types}
        self._all_categories = set(self.catalog.categories())


# ── per-capability impact ─────────────────────────────────────────────────────
@dataclass
class CapabilityImpact:
    capability_id: str
    category: str
    expected_value: float
    expected_findings: float
    expected_verification_rate: float
    expected_chain_contribution: float
    expected_pattern_contribution: float
    reliability: float
    total_events: int

    def to_dict(self) -> Dict:
        return self.__dict__.copy()


class CapabilityImpactAnalyzer:
    def __init__(self, ctx: Optional[SimulationContext] = None):
        self.ctx = ctx or SimulationContext()
        self._cache: Dict[str, CapabilityImpact] = {}

    def impact(self, capability_id: str) -> CapabilityImpact:
        if capability_id in self._cache:
            return self._cache[capability_id]
        ctx = self.ctx
        cap = ctx.catalog.get(capability_id)
        if cap is None:
            raise KeyError(f"unknown capability: {capability_id}")
        prior = min(1.0, max(0.0, cap.confidence_weight))
        srcs = [ctx.src.get(f"source.{t}") for t in cap.tools]
        srcs = [s for s in srcs if s]
        eff = _mean([s.effectiveness_score * recency_factor(s.last_success_at, ctx.now) for s in srcs])
        chain_raw = sum(s.chain_contributions for s in srcs)
        pat_raw = sum(s.unique_patterns_created for s in srcs)
        total_events = sum(s.total_events for s in srcs)

        ver_rates = [ctx.ver[t]["success_rate"] for t in cap.tools if t in ctx.ver]
        ver_rate = _mean(ver_rates) if ver_rates else (0.5 if cap.is_verification else 0.0)

        hcs = [h for h in ctx.health_by_cap.get(capability_id, []) if h.total_outcomes > 0]
        reliability = _mean([h.reliability_score for h in hcs]) if hcs else 0.5

        learned_chain = chain_raw / total_events if total_events else 0.0
        learned_pat = pat_raw / total_events if total_events else 0.0
        struct_chain = prior if cap.category in CHAIN_PRONE else prior * 0.3
        expected_chain = round(min(1.0, 0.7 * learned_chain + 0.3 * struct_chain), 4)
        expected_pat = round(min(1.0, 0.7 * learned_pat + 0.3 * prior * 0.5), 4)
        expected_findings = round(0.5 * prior + 0.5 * eff, 4)

        components = {
            "findings": expected_findings, "verification": round(ver_rate, 4),
            "reliability": round(reliability, 4), "chain": expected_chain, "pattern": expected_pat,
        }
        ev = round(sum(IMPACT_WEIGHTS[k] * v for k, v in components.items()), 4)
        imp = CapabilityImpact(
            capability_id=capability_id, category=cap.category, expected_value=ev,
            expected_findings=expected_findings, expected_verification_rate=round(ver_rate, 4),
            expected_chain_contribution=expected_chain, expected_pattern_contribution=expected_pat,
            reliability=round(reliability, 4), total_events=total_events)
        self._cache[capability_id] = imp
        return imp

    def all_impacts(self) -> List[CapabilityImpact]:
        return [self.impact(c.capability_id) for c in self.ctx.catalog.all()]


# ── workflow simulation ──────────────────────────────────────────────────────
@dataclass
class WorkflowPrediction:
    subject: str
    capabilities: List[str]
    expected_findings: float
    expected_verification_success: float
    expected_evidence_diversity: float
    expected_source_diversity: float
    expected_chain_generation: float
    expected_pattern_generation: float
    workflow_completion_probability: float

    def metrics(self) -> Dict[str, float]:
        """Flat metric map (used by the learning loop / accuracy framework)."""
        return {
            "expected_findings": self.expected_findings,
            "expected_verification_success": self.expected_verification_success,
            "expected_evidence_diversity": self.expected_evidence_diversity,
            "expected_source_diversity": self.expected_source_diversity,
            "expected_chain_generation": self.expected_chain_generation,
            "expected_pattern_generation": self.expected_pattern_generation,
            "workflow_completion_probability": self.workflow_completion_probability,
        }

    def to_dict(self) -> Dict:
        return {"subject": self.subject, "capabilities": self.capabilities, **self.metrics()}


def _subject_key(prefix: str, capabilities: List[str]) -> str:
    h = hashlib.sha1("|".join(sorted(capabilities)).encode()).hexdigest()[:12]
    return f"{prefix}:{h}"


class WorkflowSimulator:
    def __init__(self, ctx: Optional[SimulationContext] = None,
                 analyzer: Optional[CapabilityImpactAnalyzer] = None):
        self.ctx = ctx or (analyzer.ctx if analyzer else SimulationContext())
        self.analyzer = analyzer or CapabilityImpactAnalyzer(self.ctx)

    # capability resolution ----------------------------------------------------
    def _from_workflow(self, workflow_id: str) -> List[str]:
        from hydra.runtime.workflows import WorkflowStore
        tasks = WorkflowStore().get_tasks(workflow_id)
        return sorted({t["capability_id"] for t in tasks if t.get("capability_id")})

    def _from_plan(self, plan: AgentPlan) -> List[str]:
        return sorted({c for s in plan.steps for c in s.assigned_capabilities})

    def capabilities_for(self, workflow_id: str = "", agent_plan: Optional[AgentPlan] = None,
                         target: str = "", target_type: str = "web",
                         capabilities: Optional[List[str]] = None) -> List[str]:
        if capabilities:
            return sorted(set(capabilities))
        if workflow_id:
            return self._from_workflow(workflow_id)
        if agent_plan is not None:
            return self._from_plan(agent_plan)
        plan = AgentPlanner(catalog=self.ctx.catalog).plan(target or "target", target_type)
        return self._from_plan(plan)

    def simulate(self, workflow_id: str = "", agent_plan: Optional[AgentPlan] = None,
                 target: str = "", target_type: str = "web",
                 capabilities: Optional[List[str]] = None) -> WorkflowPrediction:
        caps = self.capabilities_for(workflow_id, agent_plan, target, target_type, capabilities)
        impacts = [self.analyzer.impact(c) for c in caps]
        subject = workflow_id or _subject_key("plan", caps)

        if not impacts:
            return WorkflowPrediction(subject, caps, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                                      round(self.ctx.hist_completion, 4))

        ver_caps = [i for i in impacts if i.expected_verification_rate > 0]
        finding_types = {ft for c in caps for ft in (self.ctx.catalog.get(c).supported_finding_types or [])}
        categories = {i.category for i in impacts}

        expected_findings = round(sum(i.expected_findings for i in impacts), 4)
        verification_success = round(_mean([i.expected_verification_rate for i in ver_caps]), 4)
        evidence_diversity = round(
            len(finding_types) / max(1, len(self.ctx._all_finding_types)), 4)
        source_diversity = round(len(categories) / max(1, len(self.ctx._all_categories)), 4)
        chain_gen = _or_prob([i.expected_chain_contribution for i in impacts])
        pattern_gen = _or_prob([i.expected_pattern_contribution for i in impacts])
        mean_rel = _mean([i.reliability for i in impacts])
        completion = round(0.6 * mean_rel + 0.4 * self.ctx.hist_completion, 4)

        return WorkflowPrediction(
            subject=subject, capabilities=caps, expected_findings=expected_findings,
            expected_verification_success=verification_success,
            expected_evidence_diversity=evidence_diversity,
            expected_source_diversity=source_diversity,
            expected_chain_generation=chain_gen, expected_pattern_generation=pattern_gen,
            workflow_completion_probability=completion)


# ── outcome prediction ───────────────────────────────────────────────────────
class OutcomePredictor:
    def __init__(self, ctx: Optional[SimulationContext] = None,
                 analyzer: Optional[CapabilityImpactAnalyzer] = None):
        self.ctx = ctx or (analyzer.ctx if analyzer else SimulationContext())
        self.analyzer = analyzer or CapabilityImpactAnalyzer(self.ctx)
        self.simulator = WorkflowSimulator(self.ctx, self.analyzer)

    def predict(self, workflow_id: str = "", agent_plan: Optional[AgentPlan] = None,
                target: str = "", target_type: str = "web",
                capabilities: Optional[List[str]] = None) -> Dict:
        caps = self.simulator.capabilities_for(workflow_id, agent_plan, target, target_type, capabilities)
        pred = self.simulator.simulate(capabilities=caps)

        # source-bias: Herfindahl concentration of events across involved tools.
        tool_events: Dict[str, int] = {}
        staleness: List[float] = []
        for cid in caps:
            for t in self.ctx.catalog.get(cid).tools:
                s = self.ctx.src.get(f"source.{t}")
                if s and s.total_events > 0:
                    tool_events[t] = tool_events.get(t, 0) + s.total_events
                    staleness.append(1.0 - recency_factor(s.last_success_at, self.ctx.now))
        total = sum(tool_events.values())
        bias = round(sum((n / total) ** 2 for n in tool_events.values()), 4) if total else 0.0
        stale = round(_mean(staleness), 4) if staleness else 0.5

        return {
            "subject": pred.subject, "capabilities": caps,
            "probability_of_success": pred.workflow_completion_probability,
            "probability_of_stale_results": stale,
            "probability_of_new_patterns": pred.expected_pattern_generation,
            "probability_of_new_chains": pred.expected_chain_generation,
            "probability_of_source_bias": bias,
        }


# ── strategy comparison ──────────────────────────────────────────────────────
class StrategyComparator:
    def __init__(self, ctx: Optional[SimulationContext] = None,
                 analyzer: Optional[CapabilityImpactAnalyzer] = None):
        self.ctx = ctx or (analyzer.ctx if analyzer else SimulationContext())
        self.analyzer = analyzer or CapabilityImpactAnalyzer(self.ctx)

    def _relevant_caps(self, target_type: str) -> List[str]:
        cats = set(TARGET_TYPE_CATEGORIES.get(target_type, TARGET_TYPE_CATEGORIES["default"]))
        return sorted(c.capability_id for c in self.ctx.catalog.all() if c.category in cats)

    def _score_strategy(self, name: str, caps: List[str]) -> Dict:
        weights = STRATEGIES[name]
        impacts = [self.analyzer.impact(c) for c in caps]
        comp = {
            "findings": _mean([i.expected_findings for i in impacts]),
            "verification": _mean([i.expected_verification_rate for i in impacts]),
            "reliability": _mean([i.reliability for i in impacts]),
            "chain": _mean([i.expected_chain_contribution for i in impacts]),
            "pattern": _mean([i.expected_pattern_contribution for i in impacts]),
        }
        score = round(sum(weights[k] * v for k, v in comp.items()), 4)
        events = sum(i.total_events for i in impacts)
        conf_val = round(events / (events + 50.0), 4)
        return {"strategy": name, "capability_count": len(caps),
                "expected_score": score, "confidence": _band(conf_val),
                "confidence_value": conf_val, "components": {k: round(v, 4) for k, v in comp.items()},
                "total_events": events}

    def compare(self, target_type: str = "web") -> Dict:
        relevant = self._relevant_caps(target_type)
        ver_caps = sorted(c for c in relevant if self.ctx.catalog.get(c).is_verification)
        strategy_caps = {
            "aggressive_coverage": relevant,
            "balanced_coverage": relevant,
            # verification-first: all verification caps + the highest-prior finding caps
            "verification_first": sorted(set(ver_caps) | set(sorted(
                relevant, key=lambda c: -self.ctx.catalog.get(c).confidence_weight)[:8])),
        }
        scored = [self._score_strategy(n, strategy_caps[n]) for n in STRATEGIES]
        scored.sort(key=lambda d: (-d["expected_score"], d["strategy"]))
        best = scored[0]
        for s in scored:
            s["rationale"] = (f"{s['strategy']} over {s['capability_count']} capabilities "
                              f"→ score {s['expected_score']} (confidence {s['confidence']})")
            s["tradeoffs"] = self._tradeoffs(s)
        return {"target_type": target_type, "recommended": best["strategy"], "strategies": scored}

    @staticmethod
    def _tradeoffs(s: Dict) -> str:
        c = s["components"]
        if s["strategy"] == "aggressive_coverage":
            return f"max breadth (findings {c['findings']}) but lower verification ({c['verification']})"
        if s["strategy"] == "verification_first":
            return f"max verification ({c['verification']}) but narrower breadth ({c['findings']})"
        return f"balanced breadth/verification (findings {c['findings']}, verification {c['verification']})"


# ── multi-agent simulation ───────────────────────────────────────────────────
class AgentSimulation:
    def __init__(self, ctx: Optional[SimulationContext] = None,
                 analyzer: Optional[CapabilityImpactAnalyzer] = None):
        self.ctx = ctx or (analyzer.ctx if analyzer else SimulationContext())
        self.analyzer = analyzer or CapabilityImpactAnalyzer(self.ctx)
        self.intel = AgentIntelligence(catalog=self.ctx.catalog)
        self.registry = self.intel.registry

    def report(self) -> Dict:
        base = self.intel.report()
        # predicted effectiveness: mean simulated expected_value over each agent's caps
        agent_effectiveness = []
        ownership: Dict[str, List[str]] = {}
        for a in self.registry.all():
            cap_ids = [c.capability_id for c in a.owned_capabilities(self.ctx.catalog)]
            for cid in cap_ids:
                ownership.setdefault(cid, []).append(a.agent_id)
            pred_ev = round(_mean([self.analyzer.impact(c).expected_value for c in cap_ids]), 4) \
                if cap_ids else 0.0
            agent_effectiveness.append({
                "agent_id": a.agent_id, "owned_capabilities": len(cap_ids),
                "predicted_effectiveness": pred_ev, "knowledge_agent": a.knowledge_agent})
        agent_effectiveness.sort(key=lambda r: (-r["predicted_effectiveness"], r["agent_id"]))

        overlaps = {cid: ag for cid, ag in ownership.items() if len(ag) > 1}
        # redundancy: non-knowledge agents whose every capability is also owned elsewhere
        redundancy = []
        for a in self.registry.all():
            if a.knowledge_agent:
                continue
            cap_ids = [c.capability_id for c in a.owned_capabilities(self.ctx.catalog)]
            if cap_ids and all(len(ownership.get(c, [])) > 1 for c in cap_ids):
                redundancy.append(a.agent_id)

        return {
            "agent_effectiveness": agent_effectiveness,
            "bottlenecks": base["bottlenecks"],
            "agent_overlap": {"count": len(overlaps), "capabilities": dict(sorted(overlaps.items()))},
            "agent_redundancy": sorted(redundancy),
            "under_utilized_agents": base["under_utilized_agents"],
        }


# ── workflow optimization advisor (never mutates) ────────────────────────────
class WorkflowOptimizationAdvisor:
    LOW_EV = 0.25
    LOW_DIVERSITY = 0.4

    def __init__(self, ctx: Optional[SimulationContext] = None,
                 analyzer: Optional[CapabilityImpactAnalyzer] = None):
        self.ctx = ctx or (analyzer.ctx if analyzer else SimulationContext())
        self.analyzer = analyzer or CapabilityImpactAnalyzer(self.ctx)
        self.simulator = WorkflowSimulator(self.ctx, self.analyzer)

    def recommend(self, workflow_id: str = "", agent_plan: Optional[AgentPlan] = None,
                  target: str = "", target_type: str = "web",
                  capabilities: Optional[List[str]] = None) -> Dict:
        caps = self.simulator.capabilities_for(workflow_id, agent_plan, target, target_type, capabilities)
        impacts = {c: self.analyzer.impact(c) for c in caps}
        recs: List[Dict] = []

        # remove_step: only the lowest-value sub-threshold capabilities (bounded, advisory).
        low = sorted((c for c in caps if impacts[c].expected_value < self.LOW_EV),
                     key=lambda c: (impacts[c].expected_value, c))[:10]
        for c in low:
            recs.append({"action": "remove_step", "target": c,
                         "rationale": f"low expected value ({impacts[c].expected_value})"})

        ordered = sorted(caps, key=lambda c: -impacts[c].expected_value)
        if ordered != caps:
            recs.append({"action": "reorder_step", "target": "workflow",
                         "rationale": "execute higher expected-value capabilities first",
                         "suggested_order": ordered})

        present_cats = {impacts[c].category for c in caps}
        relevant = set(TARGET_TYPE_CATEGORIES.get(target_type, TARGET_TYPE_CATEGORIES["default"]))
        for missing in sorted(relevant - present_cats):
            cands = sorted((cc for cc in self.ctx.catalog.by_category(missing)),
                           key=lambda x: -x.confidence_weight)
            if cands:
                recs.append({"action": "add_capability", "target": cands[0].capability_id,
                             "rationale": f"no capability covering category '{missing}'"})

        has_verification = any(self.ctx.catalog.get(c).is_verification for c in caps)
        has_findings = any(impacts[c].expected_findings > 0.3 for c in caps)
        if has_findings and not has_verification:
            recs.append({"action": "add_verification", "target": "workflow",
                         "rationale": "finding-producing capabilities present but no verification capability"})

        pred = self.simulator.simulate(capabilities=caps)
        if pred.expected_source_diversity < self.LOW_DIVERSITY or \
                pred.expected_evidence_diversity < self.LOW_DIVERSITY:
            recs.append({"action": "increase_diversity", "target": "workflow",
                         "rationale": f"low diversity (source {pred.expected_source_diversity}, "
                                      f"evidence {pred.expected_evidence_diversity})"})

        return {"subject": pred.subject, "capabilities": caps,
                "recommendation_count": len(recs), "recommendations": recs}


# ── decision learning store (event-sourced, derived/disposable) ──────────────
class DecisionLearningStore:
    def __init__(self, db_path: Optional[Path | str] = None):
        self.db_path = Path(db_path) if db_path else Path(
            os.environ.get("HYDRA_DECISION_DB") or _DEFAULT_DB)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(str(self.db_path), timeout=30)
        c.row_factory = sqlite3.Row
        return c

    def _init(self) -> None:
        c = self._conn()
        try:
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA synchronous=NORMAL")
            c.executescript("""
                CREATE TABLE IF NOT EXISTS prediction_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    subject_type TEXT NOT NULL, subject_key TEXT NOT NULL,
                    metric TEXT NOT NULL, predicted REAL NOT NULL,
                    occurred_at REAL NOT NULL, dedup_key TEXT, UNIQUE(dedup_key)
                );
                CREATE INDEX IF NOT EXISTS idx_pe_subj ON prediction_events(subject_key, metric);
                CREATE TABLE IF NOT EXISTS outcome_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    subject_key TEXT NOT NULL, metric TEXT NOT NULL, actual REAL NOT NULL,
                    occurred_at REAL NOT NULL, dedup_key TEXT, UNIQUE(dedup_key)
                );
                CREATE INDEX IF NOT EXISTS idx_oe_subj ON outcome_events(subject_key, metric);
            """)
            c.commit()
        finally:
            c.close()

    def record_prediction(self, subject_type: str, subject_key: str,
                          predictions: Dict[str, float], dedup_key: Optional[str] = None) -> int:
        now = time.time()
        rows = [(subject_type, subject_key, m, float(v), now,
                 (dedup_key + ":" + m) if dedup_key else None) for m, v in sorted(predictions.items())]
        c = self._conn()
        try:
            cur = c.executemany(
                "INSERT OR IGNORE INTO prediction_events (subject_type, subject_key, metric, "
                "predicted, occurred_at, dedup_key) VALUES (?,?,?,?,?,?)", rows)
            c.commit()
            return cur.rowcount
        finally:
            c.close()

    def record_outcome(self, subject_key: str, outcomes: Dict[str, float],
                       dedup_key: Optional[str] = None) -> int:
        now = time.time()
        rows = [(subject_key, m, float(v), now, (dedup_key + ":" + m) if dedup_key else None)
                for m, v in sorted(outcomes.items())]
        c = self._conn()
        try:
            cur = c.executemany(
                "INSERT OR IGNORE INTO outcome_events (subject_key, metric, actual, "
                "occurred_at, dedup_key) VALUES (?,?,?,?,?)", rows)
            c.commit()
            return cur.rowcount
        finally:
            c.close()

    def matched(self) -> List[Dict]:
        """Predicted vs actual, joined on (subject_key, metric). For each pair, the latest
        prediction and latest outcome (deterministic). Single query."""
        c = self._conn()
        try:
            rows = c.execute("""
                SELECT p.subject_key sk, p.metric metric,
                       p.predicted predicted, o.actual actual, o.ts at
                FROM (SELECT subject_key, metric, predicted,
                             MAX(occurred_at) ts FROM prediction_events
                      GROUP BY subject_key, metric) latest_p
                JOIN prediction_events p ON p.subject_key=latest_p.subject_key
                     AND p.metric=latest_p.metric AND p.occurred_at=latest_p.ts
                JOIN (SELECT subject_key, metric, actual,
                             MAX(occurred_at) ts FROM outcome_events
                      GROUP BY subject_key, metric) o
                     ON o.subject_key=p.subject_key AND o.metric=p.metric
                ORDER BY o.ts, p.subject_key, p.metric
            """).fetchall()
        finally:
            c.close()
        return [{"subject_key": r["sk"], "metric": r["metric"],
                 "predicted": float(r["predicted"]), "actual": float(r["actual"]),
                 "occurred_at": float(r["at"])} for r in rows]

    def counts(self) -> Dict[str, int]:
        c = self._conn()
        try:
            p = c.execute("SELECT COUNT(*) n FROM prediction_events").fetchone()["n"]
            o = c.execute("SELECT COUNT(*) n FROM outcome_events").fetchone()["n"]
        finally:
            c.close()
        return {"predictions": int(p), "outcomes": int(o)}

    def reset(self) -> None:
        c = self._conn()
        try:
            c.executescript("DELETE FROM prediction_events; DELETE FROM outcome_events;")
            c.commit()
        finally:
            c.close()


# ── prediction accuracy framework (read-only, reproducible) ──────────────────
class PredictionAnalytics:
    """Compares predicted vs actual recorded outcomes. Pure functions of the event log →
    reproducible. ADVISORY — never affects confidence.py / promotion.py."""

    HIGH = 0.5   # threshold separating "high" vs "low" prediction for FP/FN rates

    def __init__(self, store: Optional[DecisionLearningStore] = None):
        self.store = store or DecisionLearningStore()

    def report(self) -> Dict:
        matched = self.store.matched()
        n = len(matched)
        if n == 0:
            return {"matched_samples": 0, "forecast_accuracy": None,
                    "false_positive_rate": None, "false_negative_rate": None,
                    "calibration_error": None, "drift": None}
        errs = [abs(m["predicted"] - m["actual"]) for m in matched]
        forecast_accuracy = round(1.0 - _mean(errs), 4)
        fp = sum(1 for m in matched if m["predicted"] >= self.HIGH and m["actual"] < self.HIGH)
        fn = sum(1 for m in matched if m["predicted"] < self.HIGH and m["actual"] >= self.HIGH)
        pred_high = sum(1 for m in matched if m["predicted"] >= self.HIGH)
        pred_low = n - pred_high
        calibration_error = round(abs(_mean([m["predicted"] for m in matched])
                                      - _mean([m["actual"] for m in matched])), 4)
        # drift: accuracy of the most-recent half minus the earliest half (chronological)
        half = n // 2
        drift = None
        if half >= 1:
            early = round(1.0 - _mean(errs[:half]), 4)
            recent = round(1.0 - _mean(errs[half:]), 4)
            drift = round(recent - early, 4)
        return {
            "matched_samples": n, "forecast_accuracy": forecast_accuracy,
            "false_positive_rate": round(fp / pred_high, 4) if pred_high else 0.0,
            "false_negative_rate": round(fn / pred_low, 4) if pred_low else 0.0,
            "calibration_error": calibration_error, "drift": drift,
        }

    def health(self) -> Dict:
        """Decision-intelligence health snapshot (consumed by Phase-J governance)."""
        rep = self.report()
        counts = self.store.counts()
        acc = rep["forecast_accuracy"]
        simulation_health = round(100 * acc, 1) if acc is not None else None
        quality = _band(acc) if acc is not None else "unknown"
        return {
            "simulation_health": simulation_health,
            "prediction_quality": quality,
            "decision_drift": rep["drift"],
            "forecast_accuracy": acc,
            "matched_samples": rep["matched_samples"],
            "predictions_recorded": counts["predictions"],
            "outcomes_recorded": counts["outcomes"],
        }
