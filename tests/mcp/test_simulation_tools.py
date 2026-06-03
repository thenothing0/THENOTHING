"""Phase L MCP behavior: simulation/decision tools read-only, deterministic, no wiki mutation."""

import json

import pytest

import hydra.knowledge.confidence as confidence_mod
import mcp_server
from tests.knowledge.conftest import build_seed


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("HYDRA_WIKI_DIR", str(tmp_path / "wiki"))
    monkeypatch.setenv("HYDRA_TOOL_HEALTH_DB", str(tmp_path / "h.db"))
    monkeypatch.setenv("HYDRA_SOURCE_LEARNING_DB", str(tmp_path / "l.db"))
    monkeypatch.setenv("HYDRA_VERIFICATION_DB", str(tmp_path / "v.db"))
    monkeypatch.setenv("HYDRA_DECISION_DB", str(tmp_path / "d.db"))
    monkeypatch.setenv("HYDRA_WORKFLOWS_DB", str(tmp_path / "w.db"))
    build_seed(tmp_path / "wiki")


def _by_type():
    return json.loads(mcp_server.kb_lint())["stats"]["by_type"]


def test_simulate_workflow_tool_deterministic():
    a = json.loads(mcp_server.simulate_workflow(target="example.com", target_type="web"))
    b = json.loads(mcp_server.simulate_workflow(target="example.com", target_type="web"))
    assert a == b
    assert "expected_findings" in a and "workflow_completion_probability" in a


def test_simulate_strategy_tool():
    out = json.loads(mcp_server.simulate_strategy("web"))
    assert out["recommended"] in {"aggressive_coverage", "balanced_coverage", "verification_first"}
    assert len(out["strategies"]) == 3


def test_predict_outcome_tool():
    out = json.loads(mcp_server.predict_outcome(target="example.com", target_type="web"))
    assert "probability_of_success" in out and "probability_of_source_bias" in out


def test_capability_impact_tool():
    one = json.loads(mcp_server.capability_impact("port_scanning"))
    assert one["capability_id"] == "port_scanning"
    allc = json.loads(mcp_server.capability_impact())
    assert allc["count"] == 87
    bad = json.loads(mcp_server.capability_impact("nope"))
    assert bad.get("success") is False


def test_prediction_accuracy_and_decision_health_tools():
    acc = json.loads(mcp_server.prediction_accuracy())
    assert "forecast_accuracy" in acc and acc["matched_samples"] == 0
    dh = json.loads(mcp_server.decision_health())
    assert dh["prediction_quality"] == "unknown"


def test_agent_effectiveness_and_optimization_tools():
    ae = json.loads(mcp_server.agent_effectiveness())
    assert "agent_effectiveness" in ae and "agent_overlap" in ae
    wo = json.loads(mcp_server.workflow_optimization(target="example.com", target_type="web"))
    assert "recommendations" in wo and "recommendation_count" in wo


def test_simulation_tools_are_read_only():
    before = _by_type()
    mcp_server.simulate_workflow(target="example.com")
    mcp_server.simulate_strategy("web")
    mcp_server.predict_outcome(target="example.com")
    mcp_server.capability_impact("port_scanning")
    mcp_server.prediction_accuracy()
    mcp_server.agent_effectiveness()
    mcp_server.workflow_optimization(target="example.com")
    mcp_server.decision_health()
    assert _by_type() == before, "Phase-L simulation tools must not mutate the wiki"


def test_confidence_module_unchanged():
    assert confidence_mod.score_from_sources(["a", "b"], {"a": 0.7, "b": 0.7}).value == "high"
    assert confidence_mod.score_from_sources(["a"]).value == "low"
