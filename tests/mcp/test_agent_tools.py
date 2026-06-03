"""Phase H MCP behavior: agent catalog/plan/route/coverage read-only, no wiki/confidence mutation."""

import json

import pytest

import hydra.knowledge.confidence as confidence_mod
import mcp_server
from tests.knowledge.conftest import build_seed


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("HYDRA_WIKI_DIR", str(tmp_path / "wiki"))
    monkeypatch.setenv("HYDRA_SOURCE_LEARNING_DB", str(tmp_path / "l.db"))
    monkeypatch.setenv("HYDRA_VERIFICATION_DB", str(tmp_path / "v.db"))
    build_seed(tmp_path / "wiki")


def _by_type():
    return json.loads(mcp_server.kb_lint())["stats"]["by_type"]


def test_agent_catalog_tool():
    out = json.loads(mcp_server.agent_catalog())
    assert out["agent_count"] == 7
    assert {a["agent_id"] for a in out["agents"]} >= {"recon_agent", "verification_agent", "mobile_agent"}


def test_agent_plan_tool():
    out = json.loads(mcp_server.agent_plan("example.com", "api", prior_findings=2))
    assert out["success"] and out["steps"]
    assert out["steps"][0]["agent_id"] == "recon_agent"
    assert 0.0 <= out["expected_value"] <= 1.0


def test_agent_plan_validates_target():
    out = json.loads(mcp_server.agent_plan("-oN /etc/x"))
    assert out.get("rejected") is True


def test_agent_route_tool():
    out = json.loads(mcp_server.agent_route("example.com", "cloud"))
    assert out["success"]
    assert any(r["agent_id"] == "cloud_agent" for r in out["routes"])


def test_agent_coverage_tool():
    out = json.loads(mcp_server.agent_coverage())
    assert out["agent_count"] == 7
    assert "workflow_coverage" in out and "bottlenecks" in out
    assert out["workflow_coverage"]["coverage_pct"] == 100.0  # mobile_agent closed the gap


def test_agent_tools_are_read_only():
    before = _by_type()
    mcp_server.agent_catalog()
    mcp_server.agent_plan("example.com", "web")
    mcp_server.agent_route("example.com", "web")
    mcp_server.agent_coverage()
    assert _by_type() == before, "Phase-H agent tools must not mutate the wiki"


def test_confidence_module_unchanged():
    assert confidence_mod.score_from_sources(["a", "b"], {"a": 0.7, "b": 0.7}).value == "high"
    assert confidence_mod.score_from_sources(["a"]).value == "low"
