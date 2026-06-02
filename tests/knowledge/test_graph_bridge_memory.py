"""Graph index + bridge (auto-backlink/no-orphan) + offensive memory tests (Phase A)."""

from hydra.knowledge.bridge import find_orphan_assets, materialize_assets
from hydra.knowledge.graph_index import KnowledgeGraphIndex
from hydra.knowledge.memory import OffensiveMemory
from hydra.knowledge.schema import Confidence, NodeType
from hydra.knowledge.wiki_store import WikiStore
from hydra.recon_fusion.asset import AssetIntelligence


def _seed(store: WikiStore):
    # target <- finding -> pattern ; technique linked by finding
    store.upsert(NodeType.TARGET, "acme", {"tags": ["t"]}, "# acme\n")
    store.upsert(NodeType.PATTERN, "waf-gap", {"tags": ["p"]}, "# waf gap\nseen on [[acme]]\n")
    store.upsert(NodeType.TECHNIQUE, "cors-probe", {"tags": ["c"]}, "# cors probing\n")
    store.upsert(NodeType.FINDING, "acme-cors", {"tags": ["f"]},
                 "# acme cors\nlinks [[acme]] [[waf-gap]] [[cors-probe]] [[missing-page]]\n")


def test_graph_index_queries(tmp_path):
    store = WikiStore(tmp_path / "wiki")
    _seed(store)
    idx = KnowledgeGraphIndex.build(store)
    assert idx.stats()["nodes"] == 4
    assert "acme" in idx.neighbors("acme-cors")
    assert idx.shortest_path("acme-cors", "waf-gap") == ["acme-cors", "waf-gap"]
    assert "waf-gap" in idx.related_patterns("acme-cors")
    # dangling link [[missing-page]] is detected, not treated as a node
    assert ("acme-cors", "missing-page") in idx.dangling_links()
    assert "missing-page" not in idx.nodes


def test_attack_paths_asset_to_finding(tmp_path):
    store = WikiStore(tmp_path / "wiki")
    store.upsert(NodeType.ASSET, "api-acme-com", {"tags": ["a"]}, "# api\nhas [[acme-vuln]]\n")
    store.upsert(NodeType.FINDING, "acme-vuln", {"tags": ["f"]}, "# vuln\n")
    idx = KnowledgeGraphIndex.build(store)
    paths = idx.attack_paths(start_type="asset", end_type="finding")
    assert any(p[0] == "api-acme-com" and p[-1] == "acme-vuln" for p in paths)


def test_materialize_assets_creates_backlinks_no_orphans(tmp_path):
    store = WikiStore(tmp_path / "wiki")
    assets = [
        AssetIntelligence("api.acme.com", "subdomain",
                          ["source.subfinder", "source.amass", "source.crt_sh"],
                          Confidence.HIGH, related_targets=["acme"]),
        AssetIntelligence("dev.acme.com", "subdomain", ["source.subfinder"],
                          Confidence.LOW, related_targets=["acme"]),
    ]
    written = materialize_assets(assets, store=store)
    assert len(written) == 2
    # target auto-created and links back to both assets
    target = store.get("acme", NodeType.TARGET)
    assert "[[api-acme-com]]" in target.body
    assert "[[dev-acme-com]]" in target.body
    # the core invariant: no orphan asset pages
    assert find_orphan_assets(store) == []


def test_offensive_memory_recall(tmp_path):
    store = WikiStore(tmp_path / "wiki")
    _seed(store)
    idx = KnowledgeGraphIndex.build(store)
    hits = OffensiveMemory(store=store, index=idx).recall("cors probing", target="acme")
    slugs = [h.slug for h in hits]
    assert "cors-probe" in slugs
    # graph-proximity boost: a page near the target outranks an unrelated one
    assert hits[0].score > 0
