"""Phase E MCP behavior: feedback loop (recon_fuse→learning→selection) + no wiki mutation."""

import json

import pytest

import mcp_server


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("HYDRA_WIKI_DIR", str(tmp_path / "wiki"))
    monkeypatch.setenv("HYDRA_SOURCE_LEARNING_DB", str(tmp_path / "learn.db"))
    # committed recon fixtures (tests/_doubles/fixtures/recon) resolve by default


def _by_type():
    return json.loads(mcp_server.kb_lint())["stats"]["by_type"]


def test_full_feedback_loop_recon_fuse_to_selection():
    # recon_fuse credits contributing sources (Phase D), which adaptive selection reads (Phase E)
    mcp_server.recon_fuse("example.com")          # fixtures: subfinder/amass/assetfinder
    sel = json.loads(mcp_server.select_sources("discover_subdomains", limit=20))
    by_id = {s["source_id"]: s for s in sel["sources"]}
    assert by_id["source.subfinder"]["total_events"] > 0
    assert by_id["source.amass"]["total_events"] > 0


def test_select_sources_runnable_offline():
    sel = json.loads(mcp_server.select_sources("discover_subdomains", online=False, limit=20))
    runnable = {s["source_id"] for s in sel["sources"] if s["runnable"]}
    assert runnable == {"source.subfinder", "source.amass",
                        "source.assetfinder", "source.findomain"}


def test_select_sources_unknown_capability():
    out = json.loads(mcp_server.select_sources("does_not_exist"))
    assert out["success"] is False


def test_recon_plan_structure():
    out = json.loads(mcp_server.recon_plan("example.com", "api", prior_findings=1))
    assert out["success"] and out["steps"]
    assert out["steps"][0]["capability"] == "discover_subdomains"
    assert 0.0 <= out["expected_value"] <= 1.0
    assert out["emphasis"]["target_under_covered"] is True


def test_recon_plan_validates_target():
    out = json.loads(mcp_server.recon_plan("-oN /etc/x"))
    assert out.get("rejected") is True


def test_selection_and_planning_do_not_change_wiki():
    mcp_server.recon_fuse("example.com")          # this legitimately writes assets
    before = _by_type()
    mcp_server.select_sources("discover_subdomains")
    mcp_server.recon_plan("example.com", "web", prior_findings=3)
    after = _by_type()
    assert before == after, "Phase-E selection/planning must not mutate the wiki"
