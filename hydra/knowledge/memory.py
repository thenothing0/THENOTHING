"""
Offensive Memory — the search-first recall gate.

"Never start from zero." Before planning any action, callers query this to pull
relevant prior knowledge (techniques, patterns, hypotheses, findings, chains,
intel) from the canonical wiki, boosted by graph proximity to the target. A
writeup-RAG corpus is consulted opportunistically when available; otherwise the
offline keyword path is fully sufficient.

Pure read path — no network, no LLM. Offline-safe.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

from hydra.knowledge.graph_index import KnowledgeGraphIndex
from hydra.knowledge.schema import NodeType, slugify
from hydra.knowledge.wiki_store import WikiStore

_TOKEN_RE = re.compile(r"[a-z0-9]+")

# Knowledge types worth recalling before planning (most reusable first).
_DEFAULT_TYPES = [
    NodeType.TECHNIQUE, NodeType.PATTERN, NodeType.CHAIN,
    NodeType.FINDING, NodeType.INTEL, NodeType.HYPOTHESIS,
]


@dataclass
class KnowledgeHit:
    slug: str
    type: str
    score: float
    why: str
    citation: str
    confidence: str = ""

    def to_dict(self):
        return {"slug": self.slug, "type": self.type, "score": round(self.score, 3),
                "why": self.why, "citation": self.citation, "confidence": self.confidence}


def _tokens(text: str) -> List[str]:
    return _TOKEN_RE.findall((text or "").lower())


class OffensiveMemory:
    def __init__(self, store: Optional[WikiStore] = None,
                 index: Optional[KnowledgeGraphIndex] = None):
        self.store = store or WikiStore()
        self._index = index

    def _ensure_index(self) -> KnowledgeGraphIndex:
        if self._index is None:
            self._index = KnowledgeGraphIndex.build(self.store)
        return self._index

    def recall(self, query: str, types: Optional[List[NodeType]] = None,
               target: Optional[str] = None, limit: int = 10) -> List[KnowledgeHit]:
        types = types or _DEFAULT_TYPES
        type_vals = {t.value for t in types}
        q_tokens = set(_tokens(query))

        # Graph proximity boost set: pages near the target.
        near: set = set()
        if target:
            try:
                near = set(self._ensure_index().subgraph(slugify(target), max_depth=2))
            except Exception:
                near = set()

        hits: List[KnowledgeHit] = []
        for page in self.store.iter_pages():
            if page.type is None or page.type.value not in type_vals:
                continue
            hay_tokens = set(_tokens(page.slug)) \
                | set(_tokens(" ".join(map(str, page.meta.get("tags", []))))) \
                | set(_tokens(" ".join(map(str, page.meta.get("aliases", []))))) \
                | set(_tokens(page.body[:600]))
            overlap = q_tokens & hay_tokens
            if not overlap and target is None:
                continue
            score = float(len(overlap))
            why_bits = []
            if overlap:
                why_bits.append("matches: " + ", ".join(sorted(overlap)[:5]))
            if page.slug in near:
                score += 1.5
                why_bits.append(f"near target [[{slugify(target)}]]")
            if score <= 0:
                continue
            hits.append(KnowledgeHit(
                slug=page.slug, type=page.type.value, score=score,
                why="; ".join(why_bits) or "type match",
                citation=str(page.path),
                confidence=str(page.meta.get("confidence", "")),
            ))

        hits.sort(key=lambda h: (-h.score, h.slug))
        return hits[:limit]
