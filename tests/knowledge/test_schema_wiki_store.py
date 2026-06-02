"""Schema + WikiStore tests (Phase A): parsing, round-trip, link resolution, conservative writes."""

from hydra.knowledge.schema import (
    Confidence,
    NodeType,
    Stage,
    dump_frontmatter,
    extract_wikilinks,
    slugify,
    split_page,
)
from hydra.knowledge.wiki_store import WikiStore


def test_split_page_round_trip():
    text = '---\ntype: finding\ntags: [a, b]\ntarget: "[[acme]]"\n---\n# Title\nbody [[x]]\n'
    meta, body = split_page(text)
    assert meta["type"] == "finding"
    assert meta["tags"] == ["a", "b"]
    assert "# Title" in body
    rendered = dump_frontmatter(meta)
    assert rendered.startswith("---\ntype: finding")


def test_dump_frontmatter_preserves_unknown_keys():
    meta = {"type": "asset", "host": "x.com", "weird_custom_key": 42}
    out = dump_frontmatter(meta)
    assert "weird_custom_key: 42" in out
    assert out.index("type:") < out.index("weird_custom_key")  # type first


def test_extract_wikilinks_normalizes():
    links = extract_wikilinks("see [[Foo Bar]] and [[baz#sec]] and [[q|alias]]")
    assert "foo-bar" in links and "baz" in links and "q" in links


def test_slugify():
    assert slugify("API.Example.com") == "api-example-com"
    assert slugify("403 WAF Bypass!") == "403-waf-bypass"


def test_confidence_rank_order():
    assert Confidence.LOW.rank < Confidence.MEDIUM.rank < Confidence.HIGH.rank


def test_stage_enum_values():
    assert Stage.FINDING.value == "finding"
    assert NodeType.from_str("Report") == NodeType.REPORT


def test_wiki_store_upsert_and_merge(tmp_path):
    store = WikiStore(tmp_path / "wiki")
    page = store.upsert(NodeType.ASSET, "api.example.com",
                        meta={"host": "api.example.com", "confidence": "low"}, body="# api\n")
    assert page.path.exists()
    # merge: existing keys preserved, new value overrides, body kept when not given
    store.upsert(NodeType.ASSET, "api.example.com", meta={"confidence": "high"})
    reloaded = store.get("api-example-com", NodeType.ASSET)
    assert reloaded.meta["confidence"] == "high"
    assert reloaded.meta["host"] == "api.example.com"   # preserved
    assert "# api" in reloaded.body                      # body not clobbered


def test_wiki_store_ensure_stub(tmp_path):
    store = WikiStore(tmp_path / "wiki")
    stub = store.ensure_stub(NodeType.TECHNIQUE, "Some Technique")
    assert stub.slug == "some-technique"
    assert "stub" in stub.meta.get("tags", [])


def test_wiki_store_reads_real_wiki():
    """Sanity: the parser handles the real hand-authored wiki without error."""
    store = WikiStore()
    pages = store.list_pages()
    assert len(pages) >= 10
    assert any(p.type == NodeType.TECHNIQUE for p in pages)
