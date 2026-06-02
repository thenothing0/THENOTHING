"""
Optional RAG indexing for Report Intelligence — isolated behind a thin protocol.

Phase B's pipeline is **offline-first**: the canonical knowledge is the wiki, and
everything works with no vector store installed. Opportunistically, a distilled
report may also be indexed into the writeup RAG corpus for semantic recall. That
capability is optional and must never become a hard dependency, so the pipeline
depends only on the `RagIndexAdapter` protocol:

  * `NoOpRagAdapter` (the default) does nothing and is always available.
  * `WriteupStoreAdapter` lazily loads `mcp-writeup-server`'s `WriteupStore`
    (which itself falls back to keyword search when chromadb is absent). Any
    import/runtime failure degrades silently to a no-op.

Tests never require the optional dependency; behavior is identical with or
without it.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any, Dict, Optional, Protocol, runtime_checkable


@runtime_checkable
class RagIndexAdapter(Protocol):
    """Index a distilled report into a RAG corpus. Returns True iff indexed."""

    def index(self, slug: str, title: str, text: str,
              metadata: Optional[Dict[str, Any]] = None) -> bool:
        ...


class NoOpRagAdapter:
    """Default adapter — does nothing, always available, always offline-safe."""

    def index(self, slug: str, title: str, text: str,
              metadata: Optional[Dict[str, Any]] = None) -> bool:
        return False


class WriteupStoreAdapter:
    """Optional adapter over `mcp-writeup-server`'s `WriteupStore`.

    Loaded lazily and defensively: the writeup server lives in a hyphenated
    directory (not an importable package), so we resolve it by file path. Any
    failure (missing module, chromadb absent, runtime error) degrades to a
    silent no-op — the pipeline behaves identically.
    """

    # repo-root/mcp-writeup-server/server.py  (this file: hydra/knowledge/rag_adapter.py)
    _SERVER_PY = Path(__file__).resolve().parents[2] / "mcp-writeup-server" / "server.py"

    def __init__(self) -> None:
        self._store = None
        self._loaded = False

    def _ensure_store(self):
        if self._loaded:
            return self._store
        self._loaded = True
        try:
            spec = importlib.util.spec_from_file_location("hydra_writeup_server", self._SERVER_PY)
            if spec is None or spec.loader is None:
                return None
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            store = module.WriteupStore()
            store.initialize()  # keyword fallback if chromadb missing
            self._store = store
        except Exception:
            self._store = None
        return self._store

    def index(self, slug: str, title: str, text: str,
              metadata: Optional[Dict[str, Any]] = None) -> bool:
        store = self._ensure_store()
        if store is None:
            return False
        try:
            writeup = {"title": title or slug, "content": text}
            if metadata:
                writeup.update(metadata)
            store.add_writeup(writeup)
            return True
        except Exception:
            return False
