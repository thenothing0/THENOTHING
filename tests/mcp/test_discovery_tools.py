"""
MCP behavior tests for the Phase-C discovery tools (offline, throwaway wiki).

HYDRA_WIKI_DIR points at a tmp wiki seeded deterministically, so the canonical
wiki is never touched and runs need no chromadb / network.
"""

import json

import pytest

import mcp_server
from tests.knowledge.conftest import build_seed


@pytest.fixture(autouse=True)
def _seeded_tmp_wiki(tmp_path, monkeypatch):
    monkeypatch.setenv("HYDRA_WIKI_DIR", str(tmp_path / "wiki"))
    build_seed(tmp_path / "wiki")  # seed the same dir the MCP tools will read


def _type_counts():
    return json.loads(mcp_server.kb_lint())["stats"]["by_type"]


def test_discover_patterns_dry_run_creates_nothing():
    before = _type_counts()
    res = json.loads(mcp_server.discover_patterns())
    assert res["count"] >= 1
    assert any(c["candidate_type"] == "pattern" for c in res["candidates"])
    assert _type_counts() == before  # nothing written


def test_discover_chains_dry_run_creates_nothing():
    before = _type_counts()
    res = json.loads(mcp_server.discover_chains())
    assert res["count"] >= 1
    assert _type_counts() == before


def test_candidates_expose_explain_block():
    res = json.loads(mcp_server.discover_patterns())
    c = res["candidates"][0]
    assert "explain" in c and "confidence_inputs" in c["explain"]
    assert "recommendation" in c
    # subclass fields must survive serialization (regression guard)
    assert "signature" in c and "vuln_class" in c


def test_chain_candidate_serializes_subclass_fields():
    res = json.loads(mcp_server.discover_chains())
    c = res["candidates"][0]
    assert "steps" in c and "link_basis" in c
    assert c["link_basis"] in {"shared_target", "shared_asset", "graph_path"}


def test_confirm_candidate_materializes():
    res = json.loads(mcp_server.discover_patterns())
    idor = next(c for c in res["candidates"] if c.get("proposed_slug") == "idor-pattern")
    out = json.loads(mcp_server.confirm_candidate("pattern", idor["id"]))
    assert out["success"] and out["confirmed"]
    # the pattern page now exists in the graph
    nb = json.loads(mcp_server.graph_neighbors("idor-pattern"))
    assert "neighbors" in nb


def test_confirm_unknown_id_rejected():
    out = json.loads(mcp_server.confirm_candidate("pattern", "patt-000000000000"))
    assert out.get("rejected") is True


def test_discover_patterns_deterministic_ordering():
    a = json.loads(mcp_server.discover_patterns())["candidates"]
    b = json.loads(mcp_server.discover_patterns())["candidates"]
    assert [c["id"] for c in a] == [c["id"] for c in b]
