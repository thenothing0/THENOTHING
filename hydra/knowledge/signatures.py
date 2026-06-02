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
from hydra.knowledge.schema import NodeType
from hydra.knowledge.wiki_store import WikiPage
from hydra.research_ingestion import VULN_TYPE_PATTERNS, ResearchIngestionEngine

# Canonical synthesis pages whose signature must come ONLY from structured fields —
# never a free-text body scan (audit F-1). Their bodies are prose/educational and
# routinely mention vulnerability vocabulary they are not "about".
_STRUCTURED_ONLY_TYPES = {NodeType.PATTERN, NodeType.CHAIN}
# The recognised vulnerability-class vocabulary (keys of the shared pattern table).
_VULN_CLASS_VOCAB = frozenset(VULN_TYPE_PATTERNS)


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
        # (1) explicit `signature` frontmatter wins for any page type.
        explicit_sig = page.meta.get("signature")
        if explicit_sig and str(explicit_sig).lower() not in ("", "unknown"):
            return _normalize(explicit_sig)
        # (2) explicit `vuln_class` frontmatter (e.g. report / discovered pattern).
        explicit = page.meta.get("vuln_class")
        if explicit and str(explicit).lower() not in ("", "unknown"):
            return _normalize(explicit)

        # (3) Canonical synthesis pages (pattern/chain) are signed from STRUCTURED
        # fields only — a vuln-class tag — never from their free-text body. This is
        # the F-1 fix: e.g. `public-api-key-pitfall` mentions "broken access / idor"
        # in prose but is not an idor pattern, so a body scan must not sign it 'idor'.
        if page.type in _STRUCTURED_ONLY_TYPES:
            return self._signature_from_tags(page)

        # (4) Findings / intel (evidence pages): heuristic over tags + body, unchanged.
        tags = " ".join(str(t) for t in (page.meta.get("tags") or []))
        haystack = f"{tags}\n{page.body}"
        types: List[str] = self._engine._identify_vuln_types(haystack)
        if not types:
            return ""  # honest unknown — ungroupable
        return _normalize(sorted(types)[0])

    @staticmethod
    def _signature_from_tags(page: WikiPage) -> str:
        """Structured-only: the first tag (deterministic) that is a recognised
        vulnerability class. No body inference. Empty string if none — such a page
        simply does not participate in signature-based dedup."""
        for tag in sorted(_normalize(t) for t in (page.meta.get("tags") or [])):
            if tag in _VULN_CLASS_VOCAB:
                return tag
        return ""


# The active provider. Swap/extend by assigning a different SignatureProvider here
# or passing one into the discovery engine — discovery never hardcodes a strategy.
DEFAULT_PROVIDER: SignatureProvider = TagTechniqueVocabProvider()
