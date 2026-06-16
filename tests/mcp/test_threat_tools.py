"""
Phase U MCP behavior: threat / knowledge-fusion tools are read-only / deterministic / advisory /
NON-executing, expose a governance block, leave promotion/confidence untouched, and bring the
contract to 156.
"""

import asyncio
import json

import pytest

import hydra.knowledge.confidence as confidence_mod
import mcp_server

THREAT_TOOLS = [
    "threat_summary", "threat_graph", "threat_clusters", "threat_evolution",
    "threat_opportunities", "threat_skills", "threat_campaigns", "threat_health",
]


def test_mcp_count_at_least_156():
    # Phase U brought the registry to 156; later additions only grow it (exact count is pinned by the
    # contract baseline in test_tool_contract.py). Here we assert the threat tools are present.
    live = {t.name for t in asyncio.run(mcp_server.mcp.list_tools())}
    assert len(live) >= 156
    for t in THREAT_TOOLS:
        assert t in live


@pytest.mark.parametrize("name", THREAT_TOOLS)
def test_tool_runs_json_advisory(name):
    d = json.loads(getattr(mcp_server, name)(now=1000.0))
    assert d.get("advisory") is True


def test_tools_deterministic():
    for name in THREAT_TOOLS:
        assert getattr(mcp_server, name)(now=1000.0) == getattr(mcp_server, name)(now=1000.0)


def test_graph_edges_all_explained():
    d = json.loads(mcp_server.threat_graph(now=1000.0))
    assert d["edge_count"] >= 1
    assert all(e.get("reason") for e in d["edges"])      # no hidden inference


def test_graph_subgraph_and_unknown():
    assert json.loads(mcp_server.threat_graph(threat_id="TA0043"))["edge_count"] >= 1
    assert json.loads(mcp_server.threat_graph(threat_id="TZZZ")).get("error") == "unknown threat"


def test_clusters_deterministic_partition():
    d = json.loads(mcp_server.threat_clusters(now=1000.0))
    members = [t for c in d["clusters"] for t in c["threats"]]
    assert len(members) == len(set(members))


def test_health_via_summary_bounded():
    d = json.loads(mcp_server.threat_summary(now=1000.0))["threat_health"]
    if d.get("threat_health_score") is not None:
        assert 0.0 <= d["threat_health_score"] <= 100.0
        assert d["status"] in ("healthy", "watch", "degrading")


def test_evolution_has_buckets():
    d = json.loads(mcp_server.threat_evolution(now=1000.0))
    for k in ("rising", "declining", "stable", "emerging_patterns"):
        assert k in d


def test_governance_exposes_threat_block():
    out = json.loads(mcp_server.governance_summary())
    assert "threat_intelligence" in out


def test_confidence_module_unchanged():
    assert confidence_mod.score_from_sources(["a", "b"], {"a": 0.7, "b": 0.7}).value == "high"
    assert confidence_mod.score_from_sources(["a"]).value == "low"
