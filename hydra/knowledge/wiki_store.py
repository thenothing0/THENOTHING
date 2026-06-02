"""
WikiStore — the canonical read/write accessor for the markdown wiki.

The wiki is the single source of truth (versioned in git). This module is the
only sanctioned way to parse and mutate it programmatically. Writes are
deliberately conservative — create-if-missing, append, or section-merge — and
preserve unknown frontmatter keys, so hand-authored pages are never clobbered.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional

from hydra.knowledge.schema import (
    NodeType,
    dump_frontmatter,
    extract_wikilinks,
    slugify,
    split_page,
)

# Repo-root/wiki  (this file: hydra/knowledge/wiki_store.py)
_DEFAULT_WIKI = Path(__file__).resolve().parents[2] / "wiki"

# NodeType -> directory under wiki/
TYPE_DIR: Dict[NodeType, str] = {
    NodeType.TARGET: "targets",
    NodeType.TECHNIQUE: "techniques",
    NodeType.ASSET: "assets",
    NodeType.PATTERN: "patterns",
    NodeType.FINDING: "findings",
    NodeType.INTEL: "intel",
    NodeType.CHAIN: "chains",
    NodeType.HYPOTHESIS: "hypotheses",
    NodeType.OBSERVATION: "observations",
    NodeType.REPORT: "reports",
}


@dataclass
class WikiPage:
    slug: str
    type: Optional[NodeType]
    path: Path
    meta: Dict = field(default_factory=dict)
    body: str = ""

    @property
    def links(self) -> List[str]:
        """All [[wikilink]] slugs referenced by this page (frontmatter + body)."""
        return extract_wikilinks(self.path.read_text(encoding="utf-8")
                                 if self.path.exists() else self.render())

    def render(self) -> str:
        return dump_frontmatter(self.meta) + "\n" + self.body.lstrip("\n")


class WikiStore:
    def __init__(self, root: Optional[Path | str] = None):
        # Precedence: explicit arg > HYDRA_WIKI_DIR env (lets MCP tools/tests target a
        # throwaway wiki) > the canonical repo wiki/.
        self.root = Path(root) if root else Path(os.environ.get("HYDRA_WIKI_DIR") or _DEFAULT_WIKI)

    # ── paths ────────────────────────────────────────────────────────────
    def _dir_for(self, ntype: NodeType) -> Path:
        return self.root / TYPE_DIR[ntype]

    def path_for(self, ntype: NodeType, slug: str) -> Path:
        return self._dir_for(ntype) / f"{slugify(slug)}.md"

    # ── read ─────────────────────────────────────────────────────────────
    def iter_pages(self, ntype: Optional[NodeType] = None) -> Iterator[WikiPage]:
        dirs = [self._dir_for(ntype)] if ntype else [self.root / d for d in TYPE_DIR.values()]
        for d in dirs:
            if not d.exists():
                continue
            for p in sorted(d.glob("*.md")):
                yield self._load(p)

    def list_pages(self, ntype: Optional[NodeType] = None) -> List[WikiPage]:
        return list(self.iter_pages(ntype))

    def _load(self, path: Path) -> WikiPage:
        meta, body = split_page(path.read_text(encoding="utf-8"))
        raw_type = meta.get("type")
        try:
            ntype = NodeType.from_str(raw_type) if raw_type else None
        except ValueError:
            ntype = None
        return WikiPage(slug=path.stem, type=ntype, path=path, meta=meta, body=body)

    def get(self, slug: str, ntype: Optional[NodeType] = None) -> Optional[WikiPage]:
        slug = slugify(slug)
        if ntype:
            p = self.path_for(ntype, slug)
            return self._load(p) if p.exists() else None
        for page in self.iter_pages():
            if page.slug == slug:
                return page
        return None

    def exists(self, slug: str, ntype: Optional[NodeType] = None) -> bool:
        return self.get(slug, ntype) is not None

    # ── write (conservative) ─────────────────────────────────────────────
    def write_page(self, page: WikiPage) -> Path:
        page.path.parent.mkdir(parents=True, exist_ok=True)
        page.meta.setdefault("created", _today())
        page.meta["updated"] = _today()
        page.path.write_text(page.render(), encoding="utf-8")
        return page.path

    def upsert(self, ntype: NodeType, slug: str, meta: Dict, body: str = "",
               merge_meta: bool = True) -> WikiPage:
        """Create the page if absent; if present, merge frontmatter (preserving
        existing keys unless overwritten) and only replace the body when given.
        Never blindly clobbers a hand-authored page."""
        slug = slugify(slug)
        existing = self.get(slug, ntype)
        if existing is None:
            meta = {"type": ntype.value, **meta}
            page = WikiPage(slug=slug, type=ntype, path=self.path_for(ntype, slug),
                            meta=meta, body=body)
            self.write_page(page)
            return page
        if merge_meta:
            merged = {**existing.meta, **{k: v for k, v in meta.items() if v is not None}}
            merged["type"] = ntype.value
            existing.meta = merged
        if body:
            existing.body = body
        self.write_page(existing)
        return existing

    def ensure_stub(self, ntype: NodeType, slug: str) -> WikiPage:
        """Create a minimal TODO stub for a [[link]] target that doesn't exist yet."""
        slug = slugify(slug)
        page = self.get(slug, ntype)
        if page:
            return page
        body = f"# {slug}\n\n> _Stub created automatically as a link target. Fill in._\n"
        return self.upsert(ntype, slug, meta={"tags": ["stub"]}, body=body)

    # ── log ──────────────────────────────────────────────────────────────
    def append_log(self, op: str, summary: str) -> None:
        log = self.root / "log.md"
        line = f"\n## [{_today()}] {op} | {summary}\n"
        with log.open("a", encoding="utf-8") as fh:
            fh.write(line)


def _today() -> str:
    return time.strftime("%Y-%m-%d")
