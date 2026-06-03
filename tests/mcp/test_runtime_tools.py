"""Phase I MCP behavior: workflow tools manage runtime state only — no wiki/confidence mutation."""

import json

import pytest

import hydra.knowledge.confidence as confidence_mod
import mcp_server
from tests.knowledge.conftest import build_seed


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("HYDRA_WIKI_DIR", str(tmp_path / "wiki"))
    monkeypatch.setenv("HYDRA_WORKFLOWS_DB", str(tmp_path / "w.db"))
    build_seed(tmp_path / "wiki")


def _by_type():
    return json.loads(mcp_server.kb_lint())["stats"]["by_type"]


def test_workflow_create_and_status():
    c = json.loads(mcp_server.workflow_create("example.com", "api"))
    assert c["success"] and c["status"] == "PENDING" and c["task_count"] > 0
    st = json.loads(mcp_server.workflow_status(c["workflow_id"]))
    assert st["success"] and len(st["tasks"]) == c["task_count"]


def test_workflow_create_idempotent_via_tool():
    a = json.loads(mcp_server.workflow_create("example.com", "web"))
    b = json.loads(mcp_server.workflow_create("example.com", "web"))
    assert a["workflow_id"] == b["workflow_id"]
    assert len(json.loads(mcp_server.workflow_history())["workflows"]) == 1


def test_workflow_create_validates_target():
    out = json.loads(mcp_server.workflow_create("-oN /etc/x"))
    assert out.get("rejected") is True


def test_workflow_status_unknown():
    out = json.loads(mcp_server.workflow_status("wf-nope"))
    assert out["success"] is False


def test_workflow_history_and_runtime_summary():
    mcp_server.workflow_create("example.com", "cloud")
    hist = json.loads(mcp_server.workflow_history())
    assert hist["success"] and len(hist["workflows"]) == 1
    rep = json.loads(mcp_server.runtime_summary())
    assert set(rep) >= {"workflow_summary", "retry_statistics", "capability_runtime_coverage"}


def test_runtime_does_not_mutate_wiki():
    before = _by_type()
    mcp_server.workflow_create("example.com", "api")
    mcp_server.workflow_status("wf-anything")
    mcp_server.workflow_history()
    mcp_server.runtime_summary()
    assert _by_type() == before, "Phase-I runtime must not mutate the canonical wiki"


def test_confidence_module_unchanged():
    assert confidence_mod.score_from_sources(["a", "b"], {"a": 0.7, "b": 0.7}).value == "high"
    assert confidence_mod.score_from_sources(["a"]).value == "low"
