"""Phase K MCP behavior: adapter tools read-only, deterministic, no wiki/confidence mutation."""

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
    build_seed(tmp_path / "wiki")


def _by_type():
    return json.loads(mcp_server.kb_lint())["stats"]["by_type"]


def test_adapter_catalog_tool():
    out = json.loads(mcp_server.adapter_catalog())
    assert out["count"] >= 87
    assert out["supported_profiles"] == ["offline", "passive", "validation", "simulation"]
    one = json.loads(mcp_server.adapter_catalog(capability="port_scanning"))
    assert one["count"] >= 1
    assert all(a["capability_id"] == "port_scanning" for a in one["adapters"])


def test_adapter_coverage_tool():
    out = json.loads(mcp_server.adapter_coverage())
    assert out["adapter_coverage"]["capability_adapter_coverage_pct"] == 100.0
    assert out["capability_exercise"]["total_capabilities"] == 87


def test_adapter_health_and_summary_tools():
    one = json.loads(mcp_server.adapter_health(adapter_id="port_scanning::nmap"))
    assert one["adapter_id"] == "port_scanning::nmap"
    agg = json.loads(mcp_server.adapter_health())
    assert {"healthiest", "weakest", "failures", "timeouts"} <= set(agg)
    s = json.loads(mcp_server.adapter_summary())
    assert "total_adapters" in s and "mean_reliability" in s


def test_adapter_select_tool_deterministic():
    a = json.loads(mcp_server.adapter_select("port_scanning"))
    b = json.loads(mcp_server.adapter_select("port_scanning"))
    assert a == b
    assert a["count"] >= 1 and a["ranked_adapters"][0]["capability_id"] == "port_scanning"
    bad = json.loads(mcp_server.adapter_select("nope"))
    assert bad.get("success") is False


def test_runtime_analytics_tool():
    out = json.loads(mcp_server.runtime_analytics())
    assert "execution_profile_distribution" in out and "category_coverage" in out


def test_adapter_tools_are_read_only():
    before = _by_type()
    mcp_server.adapter_catalog()
    mcp_server.adapter_coverage()
    mcp_server.adapter_health()
    mcp_server.adapter_summary()
    mcp_server.adapter_select("port_scanning")
    mcp_server.runtime_analytics()
    assert _by_type() == before, "Phase-K adapter tools must not mutate the wiki"


def test_confidence_module_unchanged():
    assert confidence_mod.score_from_sources(["a", "b"], {"a": 0.7, "b": 0.7}).value == "high"
    assert confidence_mod.score_from_sources(["a"]).value == "low"
