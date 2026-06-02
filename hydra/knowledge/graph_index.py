"""
Graph index — the derived, rebuildable acceleration layer over the wiki.

The wiki (markdown + [[wikilinks]]) is canonical. This index is built by walking
the wiki, and can be thrown away and rebuilt at any time — it is NEVER an
authoritative store. It reuses `hydra/graph/engine.AttackGraph` for path
traversal and adds knowledge-graph queries on top.

Persistence: an optional SQLite snapshot at `data/knowledge_index.db` (gitignored,
disposable). Queries operate on the in-memory graph after `rebuild()`.
"""

from __future__ import annotations

import sqlite3
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from hydra.graph.engine import AttackGraph, GraphEdge, GraphNode
from hydra.knowledge.schema import NodeType, extract_wikilinks
from hydra.knowledge.wiki_store import WikiStore

_DB_PATH = Path(__file__).resolve().parents[2] / "data" / "knowledge_index.db"


@dataclass
class KnowledgeGraphIndex:
    nodes: Dict[str, str] = field(default_factory=dict)          # slug -> node_type
    adjacency: Dict[str, List[str]] = field(default_factory=dict)
    reverse: Dict[str, List[str]] = field(default_factory=dict)
    edges: List[Tuple[str, str]] = field(default_factory=list)
    dangling: List[Tuple[str, str]] = field(default_factory=list)  # (src, missing_dst)
    _attack: Optional[AttackGraph] = None

    # ── build ────────────────────────────────────────────────────────────
    @classmethod
    def build(cls, store: Optional[WikiStore] = None) -> "KnowledgeGraphIndex":
        store = store or WikiStore()
        idx = cls()
        pages = store.list_pages()
        for page in pages:
            idx.nodes[page.slug] = page.type.value if page.type else "unknown"
            idx.adjacency.setdefault(page.slug, [])
            idx.reverse.setdefault(page.slug, [])
        for page in pages:
            text = page.path.read_text(encoding="utf-8")
            for dst in extract_wikilinks(text):
                if dst == page.slug:
                    continue
                if dst in idx.nodes:
                    idx.edges.append((page.slug, dst))
                    idx.adjacency[page.slug].append(dst)
                    idx.reverse.setdefault(dst, []).append(page.slug)
                else:
                    idx.dangling.append((page.slug, dst))
        idx._build_attack_graph()
        return idx

    def _build_attack_graph(self) -> None:
        g = AttackGraph()
        for slug, ntype in self.nodes.items():
            g.add_node(GraphNode(id=slug, node_type=ntype, label=slug))
        for src, dst in self.edges:
            g.add_edge(GraphEdge(source_id=src, target_id=dst, edge_type="links_to"))
        self._attack = g

    # ── queries ──────────────────────────────────────────────────────────
    def neighbors(self, page: str) -> List[str]:
        out = self.adjacency.get(page, [])
        inb = self.reverse.get(page, [])
        seen, result = set(), []
        for s in list(out) + list(inb):
            if s not in seen:
                seen.add(s)
                result.append(s)
        return result

    def shortest_path(self, a: str, b: str) -> List[str]:
        """BFS over the undirected view of the link graph. [] if unreachable."""
        if a not in self.nodes or b not in self.nodes:
            return []
        if a == b:
            return [a]
        q = deque([[a]])
        visited = {a}
        while q:
            path = q.popleft()
            for nxt in self.neighbors(path[-1]):
                if nxt in visited:
                    continue
                if nxt == b:
                    return path + [nxt]
                visited.add(nxt)
                q.append(path + [nxt])
        return []

    def attack_paths(self, start_type: str = "asset", end_type: str = "finding",
                     max_depth: int = 8) -> List[List[str]]:
        if not self._attack:
            self._build_attack_graph()
        return self._attack.find_attack_paths(start_type=start_type, end_type=end_type,
                                              max_depth=max_depth)

    def _related_of_type(self, page: str, ntype: NodeType) -> List[str]:
        return [n for n in self.neighbors(page) if self.nodes.get(n) == ntype.value]

    def related_findings(self, page: str) -> List[str]:
        return self._related_of_type(page, NodeType.FINDING)

    def related_patterns(self, page: str) -> List[str]:
        return self._related_of_type(page, NodeType.PATTERN)

    def related_chains(self, page: str) -> List[str]:
        return self._related_of_type(page, NodeType.CHAIN)

    def by_type(self) -> Dict[str, List[str]]:
        out: Dict[str, List[str]] = {}
        for slug, ntype in self.nodes.items():
            out.setdefault(ntype, []).append(slug)
        return {k: sorted(v) for k, v in out.items()}

    def orphans(self) -> List[str]:
        """Pages with zero inbound links (low intelligence value per the spec)."""
        return sorted(s for s in self.nodes if not self.reverse.get(s))

    def dangling_links(self) -> List[Tuple[str, str]]:
        return list(self.dangling)

    def subgraph(self, root: str, max_depth: int = 3) -> List[str]:
        if root not in self.nodes:
            return []
        seen, frontier = {root}, [root]
        for _ in range(max_depth):
            nxt = []
            for node in frontier:
                for n in self.neighbors(node):
                    if n not in seen:
                        seen.add(n)
                        nxt.append(n)
            frontier = nxt
        return sorted(seen)

    def stats(self) -> Dict:
        return {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "dangling_links": len(self.dangling),
            "orphans": len(self.orphans()),
            "by_type": {k: len(v) for k, v in self.by_type().items()},
        }

    # ── persistence (disposable SQLite snapshot) ──────────────────────────
    def save(self, db_path: Optional[Path] = None) -> Path:
        path = Path(db_path) if db_path else _DB_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(path))
        try:
            conn.executescript(
                "DROP TABLE IF EXISTS nodes; DROP TABLE IF EXISTS edges;"
                "CREATE TABLE nodes (slug TEXT PRIMARY KEY, node_type TEXT);"
                "CREATE TABLE edges (src TEXT, dst TEXT);"
            )
            conn.executemany("INSERT INTO nodes VALUES (?,?)", list(self.nodes.items()))
            conn.executemany("INSERT INTO edges VALUES (?,?)", self.edges)
            conn.commit()
        finally:
            conn.close()
        return path


def rebuild(store: Optional[WikiStore] = None, persist: bool = True) -> Dict:
    """Rebuild the index from the canonical wiki and return a summary."""
    idx = KnowledgeGraphIndex.build(store)
    if persist:
        try:
            idx.save()
        except Exception:  # pragma: no cover - persistence is best-effort
            pass
    return idx.stats()
