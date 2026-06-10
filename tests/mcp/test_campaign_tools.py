"""
Phase Q MCP behavior: campaign tools are read-only / deterministic / advisory / NON-executing,
expose a governance block, leave promotion/confidence untouched, and bring the contract to 124.
"""

import asyncio
import json

import pytest

import hydra.knowledge.confidence as confidence_mod
import mcp_server

CAMPAIGN_TOOLS = [
    "campaign_summary", "campaign_objectives", "campaign_playbooks", "campaign_paths",
    "campaign_strategies", "campaign_simulation", "campaign_gaps", "campaign_health",
]


def test_mcp_count_is_124():
    live = {t.name for t in asyncio.run(mcp_server.mcp.list_tools())}
    assert len(live) == 124
    for t in CAMPAIGN_TOOLS:
        assert t in live


@pytest.mark.parametrize("name", CAMPAIGN_TOOLS)
def test_tool_runs_json_advisory(name):
    d = json.loads(getattr(mcp_server, name)(now=1000.0))
    assert d.get("advisory") is True


def test_tools_deterministic():
    for name in CAMPAIGN_TOOLS:
        assert getattr(mcp_server, name)(now=1000.0) == getattr(mcp_server, name)(now=1000.0)


def test_simulation_non_executing():
    d = json.loads(mcp_server.campaign_simulation(
        scenario="remove_capability", subject="http_probing", now=1000.0))
    assert d["non_executing"] is True
    assert d["advisory"] is True


def test_playbook_exposes_facets_and_dual_graphs():
    d = json.loads(mcp_server.campaign_playbooks(playbook="web_application_assessment", now=1000.0))
    for k in ("campaign_capabilities", "campaign_skills", "campaign_agents",
              "campaign_dependencies", "capability_graph", "skill_graph"):
        assert k in d


def test_health_bounded():
    d = json.loads(mcp_server.campaign_health(now=1000.0))
    if d.get("campaign_health_score") is not None:
        assert 0.0 <= d["campaign_health_score"] <= 100.0
        assert d["status"] in ("healthy", "watch", "degrading")


def test_strategies_five_metrics():
    d = json.loads(mcp_server.campaign_strategies(now=1000.0))
    assert set(d["better_per_metric"]) == {
        "coverage", "diversity", "effectiveness", "dependency_risk", "redundancy"}


def test_governance_exposes_campaign_block():
    out = json.loads(mcp_server.governance_summary())
    assert "campaign_intelligence" in out


def test_confidence_module_unchanged():
    assert confidence_mod.score_from_sources(["a", "b"], {"a": 0.7, "b": 0.7}).value == "high"
    assert confidence_mod.score_from_sources(["a"]).value == "low"
