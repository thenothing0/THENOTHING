"""
Behavior tests for the Phase-B Report Intelligence MCP tools (offline, throwaway
wiki). HYDRA_WIKI_DIR points at a tmp dir so the canonical wiki is never touched.
Runs without chromadb (the RAG adapter defaults to a no-op).
"""

import json
from pathlib import Path

import pytest

import mcp_server

FIXTURES = Path(__file__).resolve().parents[1] / "_doubles" / "fixtures" / "reports"
CHAINED = FIXTURES / "chained_authz_takeover.md"
TRIVIAL = FIXTURES / "trivial_header_misconfig.md"


@pytest.fixture(autouse=True)
def _tmp_wiki(tmp_path, monkeypatch):
    monkeypatch.setenv("HYDRA_WIKI_DIR", str(tmp_path / "wiki"))


def test_ingest_report_requires_input():
    res = json.loads(mcp_server.ingest_report())
    assert res["success"] is False


def test_ingest_report_writes_pages_and_score():
    res = json.loads(mcp_server.ingest_report(path=str(CHAINED), target="acme",
                                              title="Authz chain ATO"))
    assert res["success"] is True
    assert 1 <= res["learning_score"] <= 10 and res["learning_score"] >= 7
    assert res["report_path"] and res["intel_path"]
    assert Path(res["report_path"]).exists() and Path(res["intel_path"]).exists()


def test_ingest_report_is_idempotent():
    a = json.loads(mcp_server.ingest_report(path=str(CHAINED), target="acme", title="ATO"))
    b = json.loads(mcp_server.ingest_report(path=str(CHAINED), target="acme", title="ATO"))
    assert a["slug"] == b["slug"]
    # Re-ingest does not duplicate report pages.
    listing = json.loads(mcp_server.list_reports())
    assert listing["count"] == 1


def test_report_lookup_exposes_provenance_and_rationale():
    ing = json.loads(mcp_server.ingest_report(path=str(CHAINED), target="acme", title="ATO"))
    look = json.loads(mcp_server.report_lookup(ing["slug"]))
    assert look["success"] is True
    assert look["learning_score"] == ing["learning_score"]
    assert look["learning_score_rationale"]
    assert look["vuln_class"] == "idor"
    # The intel + target backlinks are present.
    assert any(s.endswith("-intel") for s in look["links"])


def test_list_reports_ranks_by_score_then_slug():
    # Two reports with the SAME score must tie-break deterministically by slug.
    mcp_server.ingest_report(path=str(TRIVIAL), target="acme", title="zzz trivial")
    mcp_server.ingest_report(path=str(TRIVIAL), target="acme", title="aaa trivial")
    listing = json.loads(mcp_server.list_reports())
    rows = listing["reports"]
    scores = [r["learning_score"] for r in rows]
    assert scores == sorted(scores, reverse=True)          # highest first
    # equal-score rows are ordered by slug ascending
    tied = [r["slug"] for r in rows if r["learning_score"] == rows[0]["learning_score"]]
    assert tied == sorted(tied)


def test_list_reports_min_score_filter():
    mcp_server.ingest_report(path=str(CHAINED), target="acme", title="high")
    mcp_server.ingest_report(path=str(TRIVIAL), target="acme", title="low")
    high_only = json.loads(mcp_server.list_reports(min_learning_score=7))
    assert all(r["learning_score"] >= 7 for r in high_only["reports"])
    assert high_only["count"] == 1


def test_report_lookup_missing():
    res = json.loads(mcp_server.report_lookup("does-not-exist"))
    assert res["success"] is False
