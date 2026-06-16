"""
Phase S MCP behavior: opportunity tools are read-only / deterministic / advisory / NON-executing,
expose a governance block, leave promotion/confidence untouched, and bring the contract to 140.
"""

import asyncio
import json

import pytest

import hydra.knowledge.confidence as confidence_mod
import mcp_server

OPPORTUNITY_TOOLS = [
    "opportunity_summary", "opportunity_surface", "opportunity_coverage",
    "opportunity_blindspots", "opportunity_graph", "opportunity_ranking",
    "opportunity_advisor", "opportunity_health",
]


def test_mcp_count_at_least_140():
    # Phase S brought the registry to 140; later phases only add (exact count is pinned by the
    # contract baseline in test_tool_contract.py). Here we assert the opportunity tools are present.
    live = {t.name for t in asyncio.run(mcp_server.mcp.list_tools())}
    assert len(live) >= 140
    for t in OPPORTUNITY_TOOLS:
        assert t in live


@pytest.mark.parametrize("name", OPPORTUNITY_TOOLS)
def test_tool_runs_json_advisory(name):
    d = json.loads(getattr(mcp_server, name)(now=1000.0))
    assert d.get("advisory") is True


def test_tools_deterministic():
    for name in OPPORTUNITY_TOOLS:
        assert getattr(mcp_server, name)(now=1000.0) == getattr(mcp_server, name)(now=1000.0)


def test_ranking_single_and_unknown():
    d = json.loads(mcp_server.opportunity_ranking(capability_id="nope_xyz_123"))
    assert d.get("error") == "unknown capability"


def test_ranking_is_versioned_and_explainable():
    d = json.loads(mcp_server.opportunity_ranking(now=1000.0))
    assert d["scoring_version"] >= 1
    assert d["opportunities"][0]["components"]            # every score is explainable


def test_health_via_summary_bounded():
    d = json.loads(mcp_server.opportunity_summary(now=1000.0))["opportunity_health"]
    if d.get("opportunity_health_score") is not None:
        assert 0.0 <= d["opportunity_health_score"] <= 100.0
        assert d["status"] in ("healthy", "watch", "degrading")


def test_advisor_safe_verbs_only():
    d = json.loads(mcp_server.opportunity_advisor(now=1000.0))
    safe = {"prioritize", "strengthen", "expand", "diversify", "investigate", "improve"}
    for rec in d["recommendations"]:
        assert rec["type"] in safe


def test_governance_exposes_opportunity_block():
    out = json.loads(mcp_server.governance_summary())
    assert "opportunity_intelligence" in out


def test_confidence_module_unchanged():
    assert confidence_mod.score_from_sources(["a", "b"], {"a": 0.7, "b": 0.7}).value == "high"
    assert confidence_mod.score_from_sources(["a"]).value == "low"
