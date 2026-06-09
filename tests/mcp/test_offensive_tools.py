"""
Phase P MCP behavior: offensive tools are read-only / deterministic / advisory, never mutate the
wiki, leave promotion/confidence untouched, expose a governance block, and bring the contract to
116 tools.
"""

import asyncio
import json

import pytest

import hydra.knowledge.confidence as confidence_mod
import mcp_server

OFFENSIVE_TOOLS = [
    "offensive_summary", "offensive_effectiveness", "offensive_coverage", "offensive_chains",
    "offensive_overlap", "offensive_gaps", "offensive_skills", "offensive_health",
]


def test_mcp_count_is_116():
    live = {t.name for t in asyncio.run(mcp_server.mcp.list_tools())}
    assert len(live) == 116
    for t in OFFENSIVE_TOOLS:
        assert t in live


@pytest.mark.parametrize("name", OFFENSIVE_TOOLS)
def test_tool_runs_json_advisory(name):
    d = json.loads(getattr(mcp_server, name)(now=1000.0))
    assert d.get("advisory") is True


def test_tools_deterministic():
    for name in OFFENSIVE_TOOLS:
        a = getattr(mcp_server, name)(now=1000.0)
        b = getattr(mcp_server, name)(now=1000.0)
        assert a == b, f"{name} not deterministic"


def test_chains_bounded():
    d = json.loads(mcp_server.offensive_chains(limit=3, now=1000.0))
    assert len(d["chains"]) <= 3
    assert d["bounds"]["max_depth"] >= 2
    assert d["advisory"] is True


def test_health_bounded():
    d = json.loads(mcp_server.offensive_health(now=1000.0))
    if d.get("offensive_health_score") is not None:
        assert 0.0 <= d["offensive_health_score"] <= 100.0
        assert d["status"] in ("healthy", "watch", "degrading")


def test_effectiveness_single_and_unknown():
    d = json.loads(mcp_server.offensive_effectiveness(capability_id="http_probing"))
    assert d["capability_id"] == "http_probing"
    u = json.loads(mcp_server.offensive_effectiveness(capability_id="nope_xyz_123"))
    assert u.get("error") == "unknown capability"


def test_governance_exposes_offensive_block():
    out = json.loads(mcp_server.governance_summary())
    assert "offensive_intelligence" in out


def test_confidence_module_unchanged():
    assert confidence_mod.score_from_sources(["a", "b"], {"a": 0.7, "b": 0.7}).value == "high"
    assert confidence_mod.score_from_sources(["a"]).value == "low"
