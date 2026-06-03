"""Phase D MCP behavior: feedback + source scores + opportunity ranking (offline, isolated)."""

import json

import pytest

import mcp_server
from tests.knowledge.conftest import build_seed


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("HYDRA_WIKI_DIR", str(tmp_path / "wiki"))
    monkeypatch.setenv("HYDRA_SOURCE_LEARNING_DB", str(tmp_path / "learn.db"))
    ws = build_seed(tmp_path / "wiki")
    # give the idor findings recon-source provenance so feedback can attribute them
    from hydra.knowledge.schema import NodeType
    for slug in ("acme-idor-a", "acme-idor-b"):
        p = ws.get(slug, NodeType.FINDING)
        p.meta["sources"] = ["source.subfinder", "source.crt_sh"]
        ws.write_page(p)


def _idor_id():
    cands = json.loads(mcp_server.discover_patterns())["candidates"]
    return next(c for c in cands if c["proposed_slug"] == "idor-pattern")["id"]


def test_record_outcome_and_source_scores():
    cid = _idor_id()
    out = json.loads(mcp_server.record_outcome("pattern", cid, "confirmed"))
    assert out["success"] and "source.subfinder" in out["sources_credited"]
    scores = json.loads(mcp_server.source_scores("source.subfinder"))["scores"]
    assert scores["confirmed_findings"] == 1
    assert scores["trust_score"] > 0.5


def test_record_outcome_rejects_bad_outcome():
    out = json.loads(mcp_server.record_outcome("pattern", _idor_id(), "maybe"))
    assert out["success"] is False


def test_rank_opportunities_deterministic_and_bounded():
    a = json.loads(mcp_server.rank_opportunities(limit=5))
    b = json.loads(mcp_server.rank_opportunities(limit=5))
    assert a["opportunities"] == b["opportunities"]
    assert len(a["opportunities"]) <= 5
    for o in a["opportunities"]:
        assert 0.0 <= o["score"] <= 1.0 and "components" in o


def test_prioritization_report_structure():
    mcp_server.record_outcome("pattern", _idor_id(), "confirmed")
    rep = json.loads(mcp_server.prioritization_report())
    assert set(rep) == {"successful_patterns", "effective_source_types", "accepted_evidence_combos"}
    assert any(p.get("signature") == "idor" for p in rep["successful_patterns"])


def test_feedback_does_not_touch_wiki():
    before = json.loads(mcp_server.kb_lint())["stats"]["by_type"]
    mcp_server.record_outcome("pattern", _idor_id(), "confirmed")
    mcp_server.rank_opportunities()
    after = json.loads(mcp_server.kb_lint())["stats"]["by_type"]
    assert before == after
