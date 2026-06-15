"""
Phase R MCP behavior: skill tools are read-only / deterministic / advisory / NON-executing, expose a
governance block, leave promotion/confidence untouched, and bring the contract to 132.
"""

import asyncio
import json

import pytest

import hydra.knowledge.confidence as confidence_mod
import mcp_server

SKILL_TOOLS = [
    "skill_summary", "skill_graph", "skill_dependencies", "skill_bundles",
    "skill_effectiveness", "skill_coverage", "skill_gaps", "skill_marketplace",
]


def test_mcp_count_is_132():
    live = {t.name for t in asyncio.run(mcp_server.mcp.list_tools())}
    assert len(live) == 132
    for t in SKILL_TOOLS:
        assert t in live


@pytest.mark.parametrize("name", SKILL_TOOLS)
def test_tool_runs_json_advisory(name):
    d = json.loads(getattr(mcp_server, name)(now=1000.0))
    assert d.get("advisory") is True


def test_tools_deterministic():
    for name in SKILL_TOOLS:
        assert getattr(mcp_server, name)(now=1000.0) == getattr(mcp_server, name)(now=1000.0)


def test_graph_has_dual_edges():
    d = json.loads(mcp_server.skill_graph(now=1000.0))
    assert "dependency_edges" in d and "composition_edges" in d


def test_effectiveness_single_and_unknown():
    d = json.loads(mcp_server.skill_effectiveness(skill_id="nope_xyz_123"))
    assert d.get("error") == "unknown skill"


def test_health_via_summary_bounded():
    d = json.loads(mcp_server.skill_summary(now=1000.0))["skill_health"]
    if d.get("skill_health_score") is not None:
        assert 0.0 <= d["skill_health_score"] <= 100.0
        assert d["status"] in ("healthy", "watch", "degrading")


def test_governance_exposes_skill_block():
    out = json.loads(mcp_server.governance_summary())
    assert "skill_intelligence" in out


def test_confidence_module_unchanged():
    assert confidence_mod.score_from_sources(["a", "b"], {"a": 0.7, "b": 0.7}).value == "high"
    assert confidence_mod.score_from_sources(["a"]).value == "low"
