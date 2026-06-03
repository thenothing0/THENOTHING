"""Phase G MCP behavior: catalog/coverage/rank/select read-only, no wiki/confidence mutation."""

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


def test_capability_catalog_tool():
    out = json.loads(mcp_server.capability_catalog())
    assert out["total_capabilities"] >= 75
    assert out["distinct_tools"] >= 75
    assert len(out["category_counts"]) == 9
    web = json.loads(mcp_server.capability_catalog("web"))
    assert all(c["category"] == "web" for c in web["capabilities"])


def test_capability_coverage_tool():
    out = json.loads(mcp_server.capability_coverage())
    assert out["total_capabilities"] >= 75
    assert "uncovered_capabilities" in out and "weak_capability_areas" in out


def test_rank_and_select_tools():
    ranked = json.loads(mcp_server.rank_tools("subdomain_discovery"))
    assert ranked["success"] and ranked["tools"]
    best = json.loads(mcp_server.select_tool("subdomain_discovery"))
    assert best["success"] and best["tool"]["tool"] in [t["tool"] for t in ranked["tools"]]


def test_rank_tools_unknown_capability():
    out = json.loads(mcp_server.rank_tools("does_not_exist"))
    assert out["success"] is False


def test_orchestration_is_read_only():
    before = _by_type()
    mcp_server.capability_catalog()
    mcp_server.capability_coverage()
    mcp_server.rank_tools("subdomain_discovery")
    mcp_server.select_tool("idor_verification")
    assert _by_type() == before, "Phase-G orchestration must not mutate the wiki"


def test_confidence_module_unchanged():
    assert confidence_mod.score_from_sources(["a", "b"], {"a": 0.7, "b": 0.7}).value == "high"
    assert confidence_mod.score_from_sources(["a"]).value == "low"
