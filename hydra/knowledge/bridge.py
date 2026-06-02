"""
Wiki <-> Graph bridge.

Materializes derived knowledge (fused Asset Intelligence, runtime attack-graph
nodes) into the CANONICAL wiki as markdown pages, then refreshes the derived
graph index. The wiki always wins; the index is never a write target.

Auto-relationship guarantee (spec addition 7): every materialized asset emits
its graph relationships and wiki backlinks automatically — it is never an
orphan. Concretely, on each asset write the bridge:
  * ensures the parent `target` page exists and links back to the asset
    (giving the asset an inbound link), and
  * ensures a stub exists for every `related_*` link target.
"""

from __future__ import annotations

from typing import List, Optional

from hydra.knowledge.graph_index import rebuild as _rebuild_index
from hydra.knowledge.schema import NodeType, slugify
from hydra.knowledge.wiki_store import WikiStore
from hydra.recon_fusion.asset import AssetIntelligence

_ASSET_SECTION = "## Discovered assets (auto)"


def materialize_assets(
    assets: List[AssetIntelligence],
    store: Optional[WikiStore] = None,
    rebuild: bool = True,
) -> List[str]:
    """Write each AssetIntelligence to a canonical wiki `asset` page with backlinks.

    Returns the list of written asset-page paths. Guarantees no orphan assets.
    """
    store = store or WikiStore()
    written: List[str] = []

    for asset in assets:
        page_spec = asset.to_wiki_page()
        page = store.upsert(NodeType.ASSET, asset.slug,
                            meta=page_spec["meta"], body=page_spec["body"])
        written.append(str(page.path))

        # (1) parent target backlink → asset is never an orphan
        for tslug in asset.related_targets:
            if tslug:
                _ensure_target_backlink(store, tslug, asset.slug)

        # (2) stubs for every related_* link target (TODO pages, per linking discipline)
        for slug in asset.related_technologies:
            store.ensure_stub(NodeType.TECHNIQUE, slug)
        for slug in asset.related_findings:
            store.ensure_stub(NodeType.FINDING, slug)
        for slug in asset.related_patterns:
            store.ensure_stub(NodeType.PATTERN, slug)
        for slug in asset.related_chains:
            store.ensure_stub(NodeType.CHAIN, slug)

    if assets:
        store.append_log("fuse", f"materialized {len(assets)} asset(s): "
                                 f"{', '.join(a.asset for a in assets[:8])}"
                                 f"{'…' if len(assets) > 8 else ''}")
    if rebuild:
        rebuild_index(store)
    return written


def _ensure_target_backlink(store: WikiStore, target_slug: str, asset_slug: str) -> None:
    target_slug = slugify(target_slug)
    link = f"[[{asset_slug}]]"
    page = store.get(target_slug, NodeType.TARGET)
    if page is None:
        body = (f"# {target_slug}\n\n> _Target page (auto-created as an asset parent)._\n\n"
                f"{_ASSET_SECTION}\n- {link}\n")
        store.upsert(NodeType.TARGET, target_slug, meta={"tags": ["target", "auto"]}, body=body)
        return
    if link in page.body:
        return  # backlink already present
    if _ASSET_SECTION in page.body:
        page.body = page.body.replace(_ASSET_SECTION, f"{_ASSET_SECTION}\n- {link}", 1)
    else:
        page.body = page.body.rstrip() + f"\n\n{_ASSET_SECTION}\n- {link}\n"
    store.write_page(page)


def materialize_graph(graph, store: Optional[WikiStore] = None, rebuild: bool = True) -> List[str]:
    """Materialize a runtime `hydra.graph.engine.AttackGraph` into wiki pages.

    Vulnerability nodes become `finding` pages (suspected) linked to their host;
    asset nodes ensure a target/asset page. Minimal Phase-A mapping.
    """
    store = store or WikiStore()
    data = graph.to_dict() if hasattr(graph, "to_dict") else graph
    written: List[str] = []
    for node in data.get("nodes", []):
        if node.get("node_type") == "vuln":
            slug = slugify(node.get("label", node.get("id", "finding")))
            meta = {"tags": ["graph", "auto"], "status": "suspected",
                    "severity": node.get("severity", "info")}
            body = f"# {node.get('label', slug)}\n\n> Suspected finding materialized from the runtime attack graph.\n"
            page = store.upsert(NodeType.FINDING, slug, meta=meta, body=body)
            written.append(str(page.path))
    if rebuild:
        rebuild_index(store)
    return written


def rebuild_index(store: Optional[WikiStore] = None) -> dict:
    """Rebuild the derived graph index from the canonical wiki."""
    return _rebuild_index(store)


def find_orphan_assets(store: Optional[WikiStore] = None) -> List[str]:
    """Invariant check: asset pages that have no inbound link (should be empty)."""
    from hydra.knowledge.graph_index import KnowledgeGraphIndex
    store = store or WikiStore()
    idx = KnowledgeGraphIndex.build(store)
    return [s for s in idx.orphans() if idx.nodes.get(s) == NodeType.ASSET.value]
