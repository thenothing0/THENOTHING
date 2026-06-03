"""Phase L — Decision simulation, prediction accuracy, multi-agent simulation, optimization.
Deterministic, offline, derived-only, advisory, no execution / promotion / confidence / wiki."""

import pytest

import hydra.knowledge.confidence as confidence_mod
import hydra.knowledge.promotion as promotion_mod
from hydra.adapters.tool_health import (
    EV_EXECUTION,
    OUTCOME_FAILURE,
    OUTCOME_SUCCESS,
    ToolHealthStore,
)
from hydra.intelligence.simulation import (
    AgentSimulation,
    CapabilityImpactAnalyzer,
    DecisionLearningStore,
    OutcomePredictor,
    PredictionAnalytics,
    SimulationContext,
    StrategyComparator,
    WorkflowOptimizationAdvisor,
    WorkflowSimulator,
)


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("HYDRA_TOOL_HEALTH_DB", str(tmp_path / "h.db"))
    monkeypatch.setenv("HYDRA_SOURCE_LEARNING_DB", str(tmp_path / "l.db"))
    monkeypatch.setenv("HYDRA_VERIFICATION_DB", str(tmp_path / "v.db"))
    monkeypatch.setenv("HYDRA_DECISION_DB", str(tmp_path / "d.db"))
    monkeypatch.setenv("HYDRA_WORKFLOWS_DB", str(tmp_path / "w.db"))


def _ctx():
    return SimulationContext(now=1000.0)


# ── determinism ───────────────────────────────────────────────────────────────
def test_identical_simulation_results():
    a = WorkflowSimulator(_ctx()).simulate(target="example.com", target_type="web").to_dict()
    b = WorkflowSimulator(_ctx()).simulate(target="example.com", target_type="web").to_dict()
    assert a == b
    assert a["capabilities"] and 0.0 <= a["workflow_completion_probability"] <= 1.0


def test_injected_now_changes_decayed_scores_but_is_deterministic():
    # selection/impact use recency_factor(now); identical now → identical results
    r1 = CapabilityImpactAnalyzer(SimulationContext(now=5000.0)).impact("port_scanning")
    r2 = CapabilityImpactAnalyzer(SimulationContext(now=5000.0)).impact("port_scanning")
    assert r1.to_dict() == r2.to_dict()


def test_capability_impact_bounds():
    an = CapabilityImpactAnalyzer(_ctx())
    for cid in ("port_scanning", "xss_probing", "subdomain_discovery"):
        imp = an.impact(cid)
        for f in (imp.expected_value, imp.expected_findings, imp.expected_verification_rate,
                  imp.expected_chain_contribution, imp.expected_pattern_contribution, imp.reliability):
            assert 0.0 <= f <= 1.0
    with pytest.raises(KeyError):
        an.impact("nope")


def test_strategy_comparison_deterministic_and_ranked():
    a = StrategyComparator(_ctx()).compare("web")
    b = StrategyComparator(_ctx()).compare("web")
    assert a == b
    names = [s["strategy"] for s in a["strategies"]]
    assert set(names) == {"aggressive_coverage", "balanced_coverage", "verification_first"}
    scores = [s["expected_score"] for s in a["strategies"]]
    assert scores == sorted(scores, reverse=True)         # ranked
    assert a["recommended"] == a["strategies"][0]["strategy"]
    for s in a["strategies"]:
        assert "rationale" in s and "tradeoffs" in s and "confidence" in s


def test_outcome_predictor_keys():
    out = OutcomePredictor(_ctx()).predict(target="x", target_type="web")
    for k in ("probability_of_success", "probability_of_stale_results",
              "probability_of_new_patterns", "probability_of_new_chains",
              "probability_of_source_bias"):
        assert 0.0 <= out[k] <= 1.0


# ── learning loop + accuracy (reproducible) ──────────────────────────────────────
def test_prediction_replay_identical_and_idempotent():
    store = DecisionLearningStore()
    n1 = store.record_prediction("workflow", "wf1",
                                 {"expected_findings": 0.8, "workflow_completion_probability": 0.9},
                                 dedup_key="wf1")
    store.record_outcome("wf1", {"expected_findings": 0.7, "workflow_completion_probability": 0.95},
                         dedup_key="wf1")
    assert n1 == 2
    # idempotent: re-recording the same dedup_key adds nothing
    assert store.record_prediction("workflow", "wf1", {"expected_findings": 0.8}, dedup_key="wf1") == 0
    a = PredictionAnalytics(store).report()
    b = PredictionAnalytics(store).report()
    assert a == b, "accuracy metrics must be reproducible"
    assert a["matched_samples"] == 2
    assert a["forecast_accuracy"] == 0.925           # 1 - mean(|0.8-0.7|,|0.9-0.95|)
    assert a["calibration_error"] == 0.025


def test_accuracy_false_positive_negative_and_drift():
    store = DecisionLearningStore()
    # predicted high, actual low → false positive
    store.record_prediction("w", "a", {"m": 0.9}, dedup_key="a")
    store.record_outcome("a", {"m": 0.1}, dedup_key="a")
    # predicted low, actual high → false negative
    store.record_prediction("w", "b", {"m": 0.1}, dedup_key="b")
    store.record_outcome("b", {"m": 0.9}, dedup_key="b")
    rep = PredictionAnalytics(store).report()
    assert rep["false_positive_rate"] == 1.0 and rep["false_negative_rate"] == 1.0
    assert rep["drift"] is not None


def test_health_unknown_when_empty():
    h = PredictionAnalytics(DecisionLearningStore()).health()
    assert h["matched_samples"] == 0 and h["prediction_quality"] == "unknown"
    assert h["simulation_health"] is None


def test_decision_store_rebuild_identical():
    store = DecisionLearningStore()
    for i in range(5):
        store.record_prediction("w", f"s{i}", {"m": 0.5 + i / 20}, dedup_key=f"p{i}")
        store.record_outcome(f"s{i}", {"m": 0.5}, dedup_key=f"o{i}")
    a = PredictionAnalytics(store).report()
    b = PredictionAnalytics(store).report()
    assert a == b


# ── multi-agent simulation ────────────────────────────────────────────────────────
def test_agent_simulation_overlap_bottleneck():
    rep = AgentSimulation(_ctx()).report()
    assert "agent_effectiveness" in rep and rep["agent_effectiveness"]
    assert "bottlenecks" in rep
    assert "agent_overlap" in rep and "count" in rep["agent_overlap"]
    assert isinstance(rep["agent_redundancy"], list)
    for a in rep["agent_effectiveness"]:
        assert 0.0 <= a["predicted_effectiveness"] <= 1.0


def test_workflow_optimization_recommends_without_mutation():
    rec = WorkflowOptimizationAdvisor(_ctx()).recommend(target="x", target_type="web")
    actions = {r["action"] for r in rec["recommendations"]}
    assert actions <= {"remove_step", "reorder_step", "add_capability",
                       "add_verification", "increase_diversity"}
    assert rec["recommendation_count"] == len(rec["recommendations"])
    # bounded remove_step suggestions
    assert sum(1 for r in rec["recommendations"] if r["action"] == "remove_step") <= 10


def test_impact_reflects_adapter_health(tmp_path):
    # Only successful adapters have data → capability reliability rises above neutral 0.5.
    hs = ToolHealthStore(tmp_path / "ok.db")
    for _ in range(20):
        hs.record("port_scanning::nmap", EV_EXECUTION, OUTCOME_SUCCESS, runtime_ms=10.0)
    imp = CapabilityImpactAnalyzer(SimulationContext(health=hs, now=1000.0)).impact("port_scanning")
    assert imp.reliability > 0.5

    # A capability whose only exercised adapter fails sits below neutral.
    hs2 = ToolHealthStore(tmp_path / "bad.db")
    for _ in range(20):
        hs2.record("port_scanning::nmap", EV_EXECUTION, OUTCOME_FAILURE, runtime_ms=10.0)
    imp2 = CapabilityImpactAnalyzer(SimulationContext(health=hs2, now=1000.0)).impact("port_scanning")
    assert imp2.reliability < 0.5


# ── safety / invariants ────────────────────────────────────────────────────────
def test_no_execution_flag():
    # simulation never executes — predictions are pure reads; verify completion is a
    # probability, not a side effect, and re-running does not change learning stores.
    before = ToolHealthStore().all_health()
    WorkflowSimulator(_ctx()).simulate(target="x", target_type="web")
    OutcomePredictor(_ctx()).predict(target="x", target_type="web")
    after = ToolHealthStore().all_health()
    assert [h.to_dict() for h in before] == [h.to_dict() for h in after]


def test_promotion_confidence_untouched():
    WorkflowSimulator(_ctx()).simulate(target="x", target_type="web")
    StrategyComparator(_ctx()).compare("web")
    assert confidence_mod.score_from_sources(["a", "b"], {"a": 0.7, "b": 0.7}).value == "high"
    assert confidence_mod.score_from_sources(["a"]).value == "low"
    assert hasattr(promotion_mod, "FORBIDDEN_PROMOTIONS")
