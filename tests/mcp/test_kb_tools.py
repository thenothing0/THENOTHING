"""
Behavior tests for the Phase-A Knowledge OS MCP tools (offline, throwaway wiki).

Each test points HYDRA_WIKI_DIR at a tmp dir so the canonical wiki is never
touched. recon_fuse uses the committed recon fixtures (default search path).
"""

import json

import pytest

import mcp_server


@pytest.fixture(autouse=True)
def _tmp_wiki(tmp_path, monkeypatch):
    monkeypatch.setenv("HYDRA_WIKI_DIR", str(tmp_path / "wiki"))


def test_capability_list():
    res = json.loads(mcp_server.capability_list())
    assert res["count"] == 9
    names = {c["capability"] for c in res["capabilities"]}
    assert "discover_subdomains" in names and "attack_surface_mapping" in names


def test_capability_sources_offline_vs_online():
    off = json.loads(mcp_server.capability_sources("discover_subdomains", online=False))
    runnable_off = [s for s in off["sources"] if s["runnable"]]
    assert {s["id"] for s in runnable_off} == {
        "source.subfinder", "source.amass", "source.assetfinder", "source.findomain"}
    # every source carries the stable id + perf block
    assert all(s["id"].startswith("source.") for s in off["sources"])


def test_recon_fuse_offline_writes_assets():
    res = json.loads(mcp_server.recon_fuse("example.com"))
    assert res["success"] is True
    confs = {a["asset"]: a["confidence"] for a in res["assets"]}
    assert confs["api.example.com"] == "high"        # 3 fixture sources
    assert confs["dev.example.com"] == "low"          # 1 source
    assert res["materialized_pages"]
    # asset_lookup round-trips what recon_fuse wrote
    look = json.loads(mcp_server.asset_lookup("api.example.com"))
    assert look["success"] and look["confidence"] == "high"


def test_recon_fuse_rejects_bad_domain():
    res = json.loads(mcp_server.recon_fuse("-oN /etc/x"))
    assert res.get("rejected") is True


def test_kb_lint_after_fuse_has_no_orphans():
    mcp_server.recon_fuse("example.com")
    lint = json.loads(mcp_server.kb_lint())
    # materialized assets are backlinked from their target -> zero orphans
    assert lint["stats"]["orphans"] == 0


def test_graph_neighbors_and_path():
    mcp_server.recon_fuse("example.com")
    # the target page links its discovered assets
    nb = json.loads(mcp_server.graph_neighbors("example-com"))
    assert any(n.startswith("api-example-com") for n in nb["neighbors"])
    path = json.loads(mcp_server.graph_path("example-com", "api-example-com"))
    assert path["reachable"] is True


def test_kb_promote_rejects_forbidden_transition():
    store = mcp_server.WikiStore()
    store.upsert(mcp_server._NodeType.HYPOTHESIS, "h1",
                 {"tags": ["x"], "stage": "hypothesis"}, "# h1\n")
    res = json.loads(mcp_server.kb_promote("h1", "pattern", evidence_count=3,
                                           sources="a,b,c"))
    assert res.get("rejected") is True


def test_kb_promote_valid_step():
    store = mcp_server.WikiStore()
    store.upsert(mcp_server._NodeType.HYPOTHESIS, "h2",
                 {"tags": ["x"], "stage": "hypothesis"}, "# h2\n")
    res = json.loads(mcp_server.kb_promote("h2", "finding", evidence_count=2,
                                           sources="s1,s2", scope_ok=True))
    assert res["success"] is True and res["promoted_to"] == "finding"


def test_kb_rebuild_index():
    mcp_server.recon_fuse("example.com")
    res = json.loads(mcp_server.kb_rebuild_index())
    assert res["success"] is True and res["stats"]["nodes"] >= 1


def test_kb_recall_offline():
    mcp_server.recon_fuse("example.com")
    res = json.loads(mcp_server.kb_recall("example", target="example.com"))
    assert "hits" in res
