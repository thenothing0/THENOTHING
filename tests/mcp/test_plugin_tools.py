"""Phase M MCP behavior: plugin/ecosystem tools read-only, deterministic, no wiki mutation."""

import json

import pytest

import hydra.knowledge.confidence as confidence_mod
import mcp_server
from tests.knowledge.conftest import build_seed


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("HYDRA_WIKI_DIR", str(tmp_path / "wiki"))
    monkeypatch.setenv("HYDRA_PLUGIN_HEALTH_DB", str(tmp_path / "ph.db"))
    build_seed(tmp_path / "wiki")


def _by_type():
    return json.loads(mcp_server.kb_lint())["stats"]["by_type"]


def test_plugin_catalog_and_summary_tools():
    cat = json.loads(mcp_server.plugin_catalog())
    assert cat["count"] == 6 and cat["enabled"] == 6
    s = json.loads(mcp_server.plugin_summary())
    assert s["composition"]["effective"] > 150 and s["installed_plugins"] == 6


def test_plugin_capabilities_dependencies_coverage_tools():
    caps = json.loads(mcp_server.plugin_capabilities("cloud_pack"))
    assert caps["plugin_id"] == "cloud_pack" and caps["capabilities"]
    deps = json.loads(mcp_server.plugin_dependencies("cloud_pack"))
    assert "dependencies" in deps
    cov = json.loads(mcp_server.plugin_coverage())
    assert cov["capabilities_added"] == 66 and cov["total_adapters"] > 400
    bad = json.loads(mcp_server.plugin_capabilities("nope"))
    assert bad.get("success") is False


def test_plugin_health_tool():
    out = json.loads(mcp_server.plugin_health())
    assert "plugins" in out and len(out["plugins"]) == 6


def test_capability_graph_and_paths_tools():
    g = json.loads(mcp_server.capability_graph())
    assert g["requires_acyclic"] is True and g["edge_count"] > 30
    p = json.loads(mcp_server.dependency_paths("subdomain_discovery", "dns_resolution"))
    assert p["reachable"] is True and p["path"][0] == "subdomain_discovery"
    cc = json.loads(mcp_server.critical_capabilities())
    assert cc["critical_capabilities"]


def test_ownership_tools():
    own = json.loads(mcp_server.agent_ownership())
    assert own["owned"] == own["total_capabilities"]
    conf = json.loads(mcp_server.ownership_conflicts())
    assert "ownership_conflict_count" in conf and "ownership_gap_count" in conf


def test_ecosystem_summary_tool_deterministic():
    a = json.loads(mcp_server.ecosystem_summary())
    b = json.loads(mcp_server.ecosystem_summary())
    assert a == b
    assert a["ecosystem"]["installed_plugins"] == 6
    assert "marketplace" in a


def test_plugin_tools_are_read_only():
    before = _by_type()
    mcp_server.plugin_catalog()
    mcp_server.plugin_summary()
    mcp_server.plugin_coverage()
    mcp_server.capability_graph()
    mcp_server.agent_ownership()
    mcp_server.ecosystem_summary()
    assert _by_type() == before, "Phase-M plugin tools must not mutate the wiki"


def test_confidence_module_unchanged():
    assert confidence_mod.score_from_sources(["a", "b"], {"a": 0.7, "b": 0.7}).value == "high"
    assert confidence_mod.score_from_sources(["a"]).value == "low"
