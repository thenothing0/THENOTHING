"""
AssetIntelligence — a first-class knowledge object for a discovered asset.

Every discovered asset is more than a string: it carries its evidence (which
sources found it), a confidence level (Two-Signal rule), timestamps, and its
relationships to other knowledge objects. `to_wiki_page()` renders it into the
canonical `asset` page frontmatter+body (consumed by the bridge), matching
wiki/_templates/asset.md.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List

from hydra.knowledge.schema import Confidence, slugify


def _today() -> str:
    return time.strftime("%Y-%m-%d")


@dataclass
class AssetIntelligence:
    asset: str
    type: str = "subdomain"                       # subdomain | url | ip | cloud_bucket | ...
    sources: List[str] = field(default_factory=list)   # stable source ids that found it
    confidence: Confidence = Confidence.LOW
    first_seen: str = field(default_factory=_today)
    last_seen: str = field(default_factory=_today)
    related_targets: List[str] = field(default_factory=list)
    related_technologies: List[str] = field(default_factory=list)
    related_findings: List[str] = field(default_factory=list)
    related_patterns: List[str] = field(default_factory=list)
    related_chains: List[str] = field(default_factory=list)
    scope_status: str = "unknown"

    @property
    def slug(self) -> str:
        return slugify(self.asset)

    def to_dict(self) -> Dict:
        return {
            "asset": self.asset, "type": self.type, "sources": list(self.sources),
            "confidence": self.confidence.value if isinstance(self.confidence, Confidence) else self.confidence,
            "first_seen": self.first_seen, "last_seen": self.last_seen,
            "scope_status": self.scope_status,
            "related_targets": self.related_targets,
            "related_technologies": self.related_technologies,
            "related_findings": self.related_findings,
            "related_patterns": self.related_patterns,
            "related_chains": self.related_chains,
        }

    def to_wiki_page(self) -> Dict:
        """Return {meta, body} for an `asset` wiki page (links emitted as [[...]])."""
        conf = self.confidence.value if isinstance(self.confidence, Confidence) else self.confidence
        target_link = f"[[{self.related_targets[0]}]]" if self.related_targets else ""
        meta = {
            "type": "asset",
            "tags": ["recon", "fused", self.type],
            "target": target_link,
            "host": self.asset,
            "scope_status": self.scope_status,
            "asset_type": self.type,
            "confidence": conf,
            "sources": list(self.sources),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }

        def links(items):
            return ", ".join(f"[[{i}]]" for i in items) if items else "—"

        body = (
            f"# {self.asset}\n\n"
            f"> Fused asset intelligence — confidence **{conf}** from "
            f"{len(self.sources)} source(s): {', '.join(self.sources) or '—'}.\n\n"
            "## Evidence\n"
            f"- Sources: {', '.join(self.sources) or '—'}\n"
            f"- First seen: {self.first_seen} · Last seen: {self.last_seen}\n\n"
            "## Related\n"
            f"- Target: {target_link or '—'}\n"
            f"- Technologies: {links(self.related_technologies)}\n"
            f"- Findings: {links(self.related_findings)}\n"
            f"- Patterns: {links(self.related_patterns)}\n"
            f"- Chains: {links(self.related_chains)}\n"
        )
        return {"meta": meta, "body": body}
