"""
signatures — pluggable pattern-signature derivation (Phase C).

A *signature* is the stable grouping key that decides whether two findings /
report-intel pages describe "the same reusable lesson" (and therefore a pattern
candidate). Discovery depends only on the `SignatureProvider` protocol, so new
strategies (embeddings, richer taxonomies, operator-defined rules) can be added
later **without touching discovery logic**.

The default `TagTechniqueVocabProvider` is deterministic and offline: it reuses
the existing vulnerability vocabulary (`research_ingestion._identify_vuln_types`)
and normalization (`learning_score._normalize`) over a page's tags + body, so we
never re-implement vuln-class parsing.
"""

from __future__ import annotations

from typing import List, Protocol, runtime_checkable

from hydra.knowledge.learning_score import _normalize
from hydra.knowledge.wiki_store import WikiPage
from hydra.research_ingestion import ResearchIngestionEngine


@runtime_checkable
class SignatureProvider(Protocol):
    """Derive a stable signature for a wiki page. Empty string = unknown (ungroupable)."""

    @property
    def name(self) -> str: ...

    def signature(self, page: WikiPage) -> str: ...


class TagTechniqueVocabProvider:
    """Default provider: vuln-class signature from tags + linked techniques + body vocabulary.

    Deterministic: the vulnerability vocabulary is a fixed table and we pick the
    alphabetically-first matched class, so the same page always yields the same
    signature regardless of run order.
    """

    name = "tag_technique_vocab/v1"

    def __init__(self, engine: ResearchIngestionEngine | None = None):
        self._engine = engine or ResearchIngestionEngine()

    def signature(self, page: WikiPage) -> str:
        # An explicit vuln_class on the page (e.g. report frontmatter) wins.
        explicit = page.meta.get("vuln_class")
        if explicit and str(explicit).lower() not in ("", "unknown"):
            return _normalize(explicit)

        # Otherwise derive from tags + body via the existing vuln-type vocabulary.
        tags = " ".join(str(t) for t in (page.meta.get("tags") or []))
        haystack = f"{tags}\n{page.body}"
        types: List[str] = self._engine._identify_vuln_types(haystack)
        if not types:
            return ""  # honest unknown — ungroupable
        return _normalize(sorted(types)[0])


# The active provider. Swap/extend by assigning a different SignatureProvider here
# or passing one into the discovery engine — discovery never hardcodes a strategy.
DEFAULT_PROVIDER: SignatureProvider = TagTechniqueVocabProvider()
