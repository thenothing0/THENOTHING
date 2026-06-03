"""Phase F MCP behavior: verification tools advisory, no wiki/confidence mutation."""

import json

import pytest

import hydra.knowledge.confidence as confidence_mod
import mcp_server
from tests.knowledge.conftest import build_seed


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("HYDRA_WIKI_DIR", str(tmp_path / "wiki"))
    monkeypatch.setenv("HYDRA_VERIFICATION_DB", str(tmp_path / "v.db"))
    build_seed(tmp_path / "wiki")


def _by_type():
    return json.loads(mcp_server.kb_lint())["stats"]["by_type"]


def test_record_verification_and_stats():
    out = json.loads(mcp_server.record_verification("idor", "idor_verifier", "success",
                                                    evidence_type="auth_swap", source_ids="source.subfinder"))
    assert out["success"] and out["recorded"]
    stats = json.loads(mcp_server.verification_stats())
    assert any(m["method"] == "idor_verifier" for m in stats["method_stats"])
    assert "by_source_category" in stats


def test_record_verification_idempotent():
    mcp_server.record_verification("idor", "idor_verifier", "success", dedup_key="k1")
    second = json.loads(mcp_server.record_verification("idor", "idor_verifier", "success", dedup_key="k1"))
    assert second["idempotent_skip"] is True


def test_record_verification_bad_outcome():
    out = json.loads(mcp_server.record_verification("idor", "m", "perhaps"))
    assert out["success"] is False


def test_playbook_and_tool_capabilities():
    pb = json.loads(mcp_server.verification_playbook("ssrf"))
    assert pb["success"] and pb["steps"] and any(s["method"] == "ssrf_verifier" for s in pb["steps"])
    tc = json.loads(mcp_server.tool_capabilities("verification"))
    assert tc["count"] == 6 and tc["tools"][0]["category"] == "verification"


def test_verification_does_not_mutate_wiki():
    before = _by_type()
    mcp_server.record_verification("idor", "idor_verifier", "success")
    mcp_server.verification_stats()
    mcp_server.verification_playbook("idor")
    mcp_server.tool_capabilities()
    assert _by_type() == before, "Phase-F verification learning must not touch the wiki"


def test_confidence_module_unchanged():
    assert confidence_mod.score_from_sources(["a", "b"], {"a": 0.7, "b": 0.7}).value == "high"
    assert confidence_mod.score_from_sources(["a"]).value == "low"
