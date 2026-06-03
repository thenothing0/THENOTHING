"""Phase J MCP behavior: governance tools read-only, deterministic, no wiki/confidence mutation."""

import json

import pytest

import hydra.knowledge.confidence as confidence_mod
import mcp_server
from hydra.knowledge.schema import NodeType
from hydra.knowledge.wiki_store import WikiStore
from tests.knowledge.conftest import build_seed


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("HYDRA_WIKI_DIR", str(tmp_path / "wiki"))
    monkeypatch.setenv("HYDRA_SOURCE_LEARNING_DB", str(tmp_path / "l.db"))
    monkeypatch.setenv("HYDRA_VERIFICATION_DB", str(tmp_path / "v.db"))
    monkeypatch.setenv("HYDRA_GOVERNANCE_DB", str(tmp_path / "g.db"))
    build_seed(tmp_path / "wiki")
    # add a duplicate-pattern + contradiction scenario
    ws = WikiStore(tmp_path / "wiki")
    ws.upsert(NodeType.PATTERN, "idor-pattern", {"tags": ["idor"], "vuln_class": "idor"}, "# a\n")
    ws.upsert(NodeType.PATTERN, "idor-pattern-2", {"tags": ["idor"], "vuln_class": "idor"}, "# b\n")
    ws.upsert(NodeType.FINDING, "fc", {"tags": ["idor"], "status": "confirmed", "host": "h.acme.com"}, "# c\n")
    ws.upsert(NodeType.FINDING, "fr", {"tags": ["idor"], "status": "rejected", "host": "h.acme.com"}, "# r\n")


def _by_type():
    return json.loads(mcp_server.kb_lint())["stats"]["by_type"]


def test_knowledge_health_deterministic():
    a = json.loads(mcp_server.knowledge_health())
    b = json.loads(mcp_server.knowledge_health())
    assert a == b
    assert 0.0 <= a["score"] <= 100.0
    assert "components" in a and "metrics" in a


def test_governance_summary():
    out = json.loads(mcp_server.governance_summary())
    assert set(out) >= {"knowledge_health_score", "drift", "weakest_areas", "recommendations"}


def test_drift_report():
    out = json.loads(mcp_server.drift_report())
    assert "drift_count" in out and "findings" in out


def test_duplicate_and_contradiction_tools():
    dup = json.loads(mcp_server.duplicate_patterns())
    assert "idor" in dup["duplicate_groups"]
    con = json.loads(mcp_server.contradiction_report())
    assert con["count"] >= 1 and con["contradictions"][0]["host"] == "h.acme.com"


def test_stale_entities_tool():
    out = json.loads(mcp_server.stale_entities())
    assert "stale_entities" in out


def test_governance_is_read_only():
    before = _by_type()
    mcp_server.governance_summary()
    mcp_server.drift_report()
    mcp_server.knowledge_health()
    mcp_server.stale_entities()
    mcp_server.duplicate_patterns()
    mcp_server.contradiction_report()
    assert _by_type() == before, "Phase-J governance must not mutate the canonical wiki"


def test_confidence_module_unchanged():
    assert confidence_mod.score_from_sources(["a", "b"], {"a": 0.7, "b": 0.7}).value == "high"
    assert confidence_mod.score_from_sources(["a"]).value == "low"
