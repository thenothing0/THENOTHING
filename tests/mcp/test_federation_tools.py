"""Phase N MCP behavior: federation tools read-only/deterministic/advisory, metadata-only,
no wiki mutation, promotion/confidence untouched."""

import json

import pytest

import hydra.knowledge.confidence as confidence_mod
import mcp_server
from tests.knowledge.conftest import build_seed


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("HYDRA_WIKI_DIR", str(tmp_path / "wiki"))
    monkeypatch.setenv("HYDRA_FEDERATION_DB", str(tmp_path / "federation.db"))
    build_seed(tmp_path / "wiki")


def _by_type():
    return json.loads(mcp_server.kb_lint())["stats"]["by_type"]


def _import_a_peer(name="beta"):
    digest = json.loads(mcp_server.export_digest(node_name=name))["digest"]
    return mcp_server.import_digest(json.dumps(digest), peer_id=f"peer:{name}")


def test_export_digest_metadata_only_and_deterministic():
    a = json.loads(mcp_server.export_digest(node_name="alpha"))
    b = json.loads(mcp_server.export_digest(node_name="alpha"))
    assert a == b and a["success"] is True
    blob = json.dumps(a["digest"])
    for forbidden in ("target", "evidence_content", "source_id", "\"host\"", "finding_id"):
        assert forbidden not in blob


def test_import_digest_idempotent_and_guarded():
    first = json.loads(_import_a_peer())
    second = json.loads(_import_a_peer())
    assert first["imported"] is True and second["deduplicated"] is True
    bad = json.loads(mcp_server.import_digest(json.dumps({"origin_peer_id": "x",
                                                          "target": "victim.com"})))
    assert bad["success"] is False and "metadata" in bad["error"]


def test_trend_and_health_tools():
    _import_a_peer("beta")
    _import_a_peer("gamma")
    caps = json.loads(mcp_server.capability_trends())
    assert caps["capabilities"] and "ecosystem_effectiveness" in caps
    ver = json.loads(mcp_server.verification_trends())
    assert "methods" in ver and "evidence_classes" in ver
    src = json.loads(mcp_server.source_trends())
    assert "source_categories" in src
    health = json.loads(mcp_server.federation_health())
    assert health["mesh"]["contributing_peers"] == 2 and health["advisory"] is True


def test_consensus_and_opportunities_advisory():
    _import_a_peer("beta")
    rep = json.loads(mcp_server.federation_consensus())
    assert rep["advisory"] is True
    opp = json.loads(mcp_server.ecosystem_opportunities())
    assert opp["advisory"] is True and "recommendations" in opp


def test_peers_and_summary_tools():
    mcp_server._FederationRegistry(mcp_server._ExchangeStore()).register_peer(
        "beta", protocol_version="1.0.0", capability_count=153, occurred_at=10.0)
    peers = json.loads(mcp_server.federation_peers())
    assert peers["total_peers"] == 1 and peers["peers"][0]["compatible"] is True
    summ = json.loads(mcp_server.federation_summary())
    assert summ["distinct_peers"] == 1


def test_federation_tools_never_mutate_wiki():
    before = _by_type()
    _import_a_peer("beta")
    mcp_server.capability_trends()
    mcp_server.verification_trends()
    mcp_server.source_trends()
    mcp_server.federation_consensus()
    mcp_server.ecosystem_opportunities()
    mcp_server.federation_health()
    assert _by_type() == before, "Phase-N federation tools must not mutate the wiki"


def test_confidence_module_unchanged():
    _import_a_peer("beta")
    assert confidence_mod.score_from_sources(["a", "b"], {"a": 0.7, "b": 0.7}).value == "high"
    assert confidence_mod.score_from_sources(["a"]).value == "low"
