"""Phase N — Federated Knowledge Exchange & Intelligence Mesh.

Deterministic, offline, metadata-only, advisory. Proves federation exchanges AGGREGATED
METADATA ONLY and never touches promotion.py / confidence.py / the canonical wiki.
"""

import json

import pytest

import hydra.knowledge.confidence as confidence_mod
import hydra.knowledge.promotion as promotion_mod
from hydra.federation.consensus import ConsensusEngine
from hydra.federation.digest import (
    CapabilityDigest,
    KnowledgeDigestGenerator,
    PluginDigest,
    VerificationDigest,
)
from hydra.federation.intelligence import IntelligenceMesh
from hydra.federation.marketplace import FederationMarketplace
from hydra.federation.registry import FederationRegistry
from hydra.federation.safety import (
    FederationSafetyError,
    assert_safe,
    deterministic_id,
    scan_forbidden,
    semver_compatible,
)
from hydra.federation.store import (
    EV_DIGEST_IMPORT,
    EV_PEER,
    KnowledgeExchangeStore,
)


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("HYDRA_FEDERATION_DB", str(tmp_path / "federation.db"))


def _store():
    return KnowledgeExchangeStore()


def _digest(node="alpha", now=0.0):
    return KnowledgeDigestGenerator(node_name=node).generate(now=now)


def _seed(store, nodes=("alpha", "beta", "gamma"), now=100.0):
    """Register peers and import each one's digest once (deterministic)."""
    reg = FederationRegistry(store)
    for i, n in enumerate(nodes):
        p = reg.register_peer(n, version="1.2.0", protocol_version="1.0.0",
                              capability_count=153, adapter_count=439,
                              categories=["cloud", "web"], occurred_at=now + i)
        store.record(EV_DIGEST_IMPORT, _digest(n), peer_id=p.peer_id, occurred_at=now + i + 0.5)
    return reg


# ── safety guard (metadata only) ────────────────────────────────────────────────
def test_safety_rejects_raw_knowledge():
    for leaky in ({"target": "victim.com"}, {"evidence_content": "x"},
                  {"finding": {}}, {"source_id": "source.fofa"},
                  {"a": [{"api_key": "sk-1"}]}, {"host": "1.2.3.4"}):
        assert scan_forbidden(leaky), f"should flag {leaky}"
        with pytest.raises(FederationSafetyError):
            assert_safe(leaky)


def test_safety_allows_aggregate_labels():
    # abstract labels are values, not keys → allowed (category 'secrets', evidence_class …)
    ok = {"source_category": "secrets", "method_success": [{"method": "replay"}],
          "evidence_class_success": [{"evidence_class": "http_response", "success_rate": 0.9}]}
    assert scan_forbidden(ok) == []
    assert_safe(ok)  # no raise


def test_store_blocks_forbidden_payload():
    with pytest.raises(FederationSafetyError):
        _store().record(EV_DIGEST_IMPORT, {"target": "acme.com"}, peer_id="p")


def test_digest_envelope_is_metadata_only():
    env = _digest()
    assert scan_forbidden(env) == []
    # source identities are never present — only categories
    blob = json.dumps(env)
    assert "source_id" not in blob


# ── determinism / rebuild-identical / idempotency ───────────────────────────────
def test_digest_rebuild_identical():
    a = KnowledgeDigestGenerator(node_name="alpha").generate(now=0.0)
    b = KnowledgeDigestGenerator(node_name="alpha").generate(now=0.0)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    assert a["origin_peer_id"] == deterministic_id("peer", "alpha", "")


def test_exchange_idempotent():
    store = _store()
    d = _digest()
    assert store.record(EV_DIGEST_IMPORT, d, peer_id="p", occurred_at=1.0) is True
    assert store.record(EV_DIGEST_IMPORT, d, peer_id="p", occurred_at=1.0) is False
    assert store.summary()["imported_digests"] == 1


def test_store_rebuildable_from_log():
    store = _store()
    _seed(store)
    before = IntelligenceMesh(store).federation_health()
    # delete the WAL/db content and re-import the same events → identical intelligence
    store.reset()
    _seed(store)
    assert IntelligenceMesh(store).federation_health() == before


# ── peer registry ───────────────────────────────────────────────────────────────
def test_peer_ids_deterministic_and_semver():
    store = _store()
    reg = FederationRegistry(store)
    p1 = reg.register_peer("acme", protocol_version="1.0.0", occurred_at=1.0)
    p2 = reg.register_peer("acme", protocol_version="1.4.0", occurred_at=2.0)  # re-announce
    assert p1.peer_id == p2.peer_id == FederationRegistry.peer_id_for("acme")
    assert len(reg.peers()) == 1                       # same peer, latest wins
    assert semver_compatible("1.9.0") and not semver_compatible("2.0.0")


def test_trust_and_health_derived():
    store = _store()
    reg = FederationRegistry(store)
    good = reg.register_peer("good", protocol_version="1.0.0", occurred_at=1.0)
    bad = reg.register_peer("bad", protocol_version="2.0.0", occurred_at=1.0)
    assert good.compatible and good.health == "announced" and good.trust_score == 0.5
    assert not bad.compatible and bad.health == "incompatible" and bad.trust_score == 0.0
    # an exchange raises trust and flips health → active
    store.record(EV_DIGEST_IMPORT, _digest("good"), peer_id=good.peer_id, occurred_at=2.0)
    refreshed = reg.get_peer(good.peer_id)
    assert refreshed.health == "active" and refreshed.trust_score > 0.5


def test_stale_health_with_injected_now():
    store = _store()
    reg = FederationRegistry(store)
    p = reg.register_peer("old", protocol_version="1.0.0", occurred_at=0.0)
    later = 0.0 + 60 * 24 * 3600          # 60 days later
    assert reg.get_peer(p.peer_id, now=later).health == "stale"


# ── digest structure ────────────────────────────────────────────────────────────
def test_capability_digests_cover_effective_catalog():
    env = _digest()
    caps = env["capability_digests"]
    assert len(caps) == 153                            # core(87) + 6 reference packs(66)
    ids = [c["capability_id"] for c in caps]
    assert ids == sorted(ids)                          # deterministic order
    pd = PluginDigest.from_dict(env["plugin_digest"])
    assert pd.plugin_capability_count == 66 and pd.effective_capabilities == 153


def test_digest_dataclass_roundtrip():
    cd = CapabilityDigest("x", "web", 3, 1, 0.7)
    assert CapabilityDigest.from_dict(cd.to_dict()) == cd
    vd = VerificationDigest(method_success=[{"method": "m", "success_rate": 0.5}],
                            evidence_class_success=[], verification_effectiveness=0.5)
    assert VerificationDigest.from_dict(vd.to_dict()) == vd


# ── intelligence mesh ───────────────────────────────────────────────────────────
def test_mesh_aggregates_across_peers():
    store = _store()
    _seed(store, nodes=("alpha", "beta", "gamma"))
    mesh = IntelligenceMesh(store)
    health = mesh.federation_health()
    assert health["contributing_peers"] == 3 and health["imported_digests"] == 3
    pop = mesh.capability_popularity()
    assert pop and all(p["peer_count"] == 3 for p in pop)   # every peer advertises all caps
    assert pop == sorted(pop, key=lambda d: (-d["peer_count"], -d["total_exercise"],
                                             d["capability_id"]))
    trends = mesh.plugin_adoption_trends()
    assert any(t["plugin_id"] == "cloud_pack" and t["adopting_peers"] == 3 for t in trends)


def test_mesh_empty_is_safe():
    mesh = IntelligenceMesh(_store())
    assert mesh.capability_popularity() == []
    assert mesh.federation_health()["contributing_peers"] == 0


# ── consensus (advisory) ────────────────────────────────────────────────────────
def test_consensus_advisory_only():
    store = _store()
    _seed(store, nodes=("a", "b", "c"))
    ce = ConsensusEngine(store)
    rep = ce.consensus_report()
    assert rep["advisory"] is True
    one = ce.capability_consensus(rep["top_consensus"][0]["capability_id"]) \
        if rep["top_consensus"] else ce.capability_consensus("nope")
    assert set(one) >= {"consensus_confidence", "disagreement_score", "diversity_score",
                        "federation_confidence", "recommendation", "advisory"}


# ── marketplace (advisory) ──────────────────────────────────────────────────────
def test_marketplace_missing_capability_detected():
    store = _store()
    # Build a peer digest that advertises a capability the local catalog lacks.
    env = _digest("ext")
    env["capability_digests"].append(
        CapabilityDigest("exotic_cap", "quantum", 5, 0, 0.9).to_dict())
    reg = FederationRegistry(store)
    p = reg.register_peer("ext", protocol_version="1.0.0", occurred_at=1.0)
    store.record(EV_DIGEST_IMPORT, env, peer_id=p.peer_id, occurred_at=2.0)
    # second peer too, so min_peers=2 is satisfied
    env2 = _digest("ext2")
    env2["capability_digests"].append(
        CapabilityDigest("exotic_cap", "quantum", 1, 0, 0.4).to_dict())
    p2 = reg.register_peer("ext2", protocol_version="1.0.0", occurred_at=3.0)
    store.record(EV_DIGEST_IMPORT, env2, peer_id=p2.peer_id, occurred_at=4.0)
    opp = FederationMarketplace(store).ecosystem_opportunities()
    assert any(m["capability_id"] == "exotic_cap" for m in opp["missing_capabilities"])
    assert opp["advisory"] is True


# ── invariants ──────────────────────────────────────────────────────────────────
def test_promotion_and_confidence_untouched():
    _seed(_store())
    assert confidence_mod.score_from_sources(["a", "b"], {"a": 0.7, "b": 0.7}).value == "high"
    assert confidence_mod.score_from_sources(["a"]).value == "low"
    assert hasattr(promotion_mod, "FORBIDDEN_PROMOTIONS")


def test_federation_never_writes_wiki(tmp_path, monkeypatch):
    # Point the wiki at an empty dir; a full federation cycle must create no pages there.
    wiki = tmp_path / "wiki"
    wiki.mkdir()
    monkeypatch.setenv("HYDRA_WIKI_DIR", str(wiki))
    store = _store()
    _seed(store)
    IntelligenceMesh(store).federation_health()
    ConsensusEngine(store).consensus_report()
    FederationMarketplace(store).ecosystem_opportunities()
    assert list(wiki.rglob("*.md")) == []


def test_only_three_event_types_and_append_only():
    store = _store()
    with pytest.raises(ValueError):
        store.record("mutate_wiki", {})
    _seed(store)
    types = set(store.counts_by_type())
    assert types <= {EV_PEER, EV_DIGEST_IMPORT, "digest_export"}
