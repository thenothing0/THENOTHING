"""Knowledge Confidence Engine (Phase 10.2).

Every knowledge object carries confidence metadata. Knowledge self-ranks
so higher-confidence items influence reasoning more heavily.

Confidence = f(source_count, confirmations, ai_agreement, freshness, reliability)
"""

import logging
import time
from typing import Any

from hydra.services.base import BaseService

logger = logging.getLogger("hydra.services.confidence")

CONFIDENCE_FACTORS = (
    "source_count", "independent_confirmations", "ai_agreement",
    "human_verification", "freshness", "reliability",
)

CONFIDENCE_BANDS = {
    "verified": (0.8, 1.0),
    "high": (0.6, 0.8),
    "medium": (0.4, 0.6),
    "low": (0.2, 0.4),
    "unverified": (0.0, 0.2),
}

DECAY_HALF_LIFE_DAYS = 90


class ConfidenceScore:
    __slots__ = (
        "slug", "score", "band", "source_count", "confirmations",
        "ai_agreement", "human_verified", "freshness", "reliability",
        "last_updated", "last_validated",
    )

    def __init__(self, slug: str, source_count: int = 1,
                 confirmations: int = 0, ai_agreement: float = 0.0,
                 human_verified: bool = False, freshness: float = 1.0,
                 reliability: float = 0.5, last_updated: float = 0.0,
                 last_validated: float = 0.0):
        self.slug = slug
        self.source_count = source_count
        self.confirmations = confirmations
        self.ai_agreement = ai_agreement
        self.human_verified = human_verified
        self.freshness = freshness
        self.reliability = reliability
        self.last_updated = last_updated or time.time()
        self.last_validated = last_validated
        self.score = self._compute()
        self.band = self._band()

    def _compute(self) -> float:
        source_w = min(self.source_count / 5.0, 1.0) * 0.2
        confirm_w = min(self.confirmations / 3.0, 1.0) * 0.2
        ai_w = self.ai_agreement * 0.15
        human_w = (1.0 if self.human_verified else 0.0) * 0.15
        fresh_w = self.freshness * 0.15
        rel_w = self.reliability * 0.15
        return round(min(source_w + confirm_w + ai_w + human_w + fresh_w + rel_w, 1.0), 4)

    def _band(self) -> str:
        for band_name, (lo, hi) in CONFIDENCE_BANDS.items():
            if lo <= self.score < hi:
                return band_name
        return "verified" if self.score >= 0.8 else "unverified"

    def to_dict(self) -> dict:
        return {
            "slug": self.slug,
            "score": self.score,
            "band": self.band,
            "source_count": self.source_count,
            "confirmations": self.confirmations,
            "ai_agreement": self.ai_agreement,
            "human_verified": self.human_verified,
            "freshness": self.freshness,
            "reliability": self.reliability,
            "last_updated": self.last_updated,
            "last_validated": self.last_validated,
        }


class ConfidenceService(BaseService):
    """Knowledge confidence scoring and self-ranking."""

    def score(self, slug: str, source_count: int = 1,
              confirmations: int = 0, ai_agreement: float = 0.0,
              human_verified: bool = False, reliability: float = 0.5,
              last_updated: float = 0.0) -> dict:
        """Compute confidence score for a knowledge object."""
        freshness = self._compute_freshness(last_updated or time.time())
        cs = ConfidenceScore(
            slug=slug,
            source_count=source_count,
            confirmations=confirmations,
            ai_agreement=ai_agreement,
            human_verified=human_verified,
            freshness=freshness,
            reliability=reliability,
            last_updated=last_updated or time.time(),
        )
        self._emit("confidence.scored", {
            "slug": slug, "score": cs.score, "band": cs.band,
        })
        return cs.to_dict()

    def score_batch(self, items: list[dict]) -> list[dict]:
        """Score multiple knowledge objects."""
        return [self.score(**item) for item in items]

    def rank(self, slugs: list[str], scores: dict[str, dict] | None = None) -> list[dict]:
        """Rank knowledge objects by confidence."""
        if scores is None:
            scores = {}
        ranked = []
        for slug in slugs:
            if slug in scores:
                ranked.append(scores[slug])
            else:
                ranked.append(self.score(slug))
        ranked.sort(key=lambda x: x["score"], reverse=True)
        return ranked

    def decay_check(self, last_updated: float, threshold: float = 0.3) -> dict:
        """Check if knowledge has decayed below threshold."""
        freshness = self._compute_freshness(last_updated)
        below = freshness < threshold
        return {
            "freshness": round(freshness, 4),
            "threshold": threshold,
            "decayed": below,
            "age_days": round((time.time() - last_updated) / 86400, 1),
        }

    def get_band(self, score_val: float) -> str:
        """Get the confidence band for a score."""
        for band_name, (lo, hi) in CONFIDENCE_BANDS.items():
            if lo <= score_val < hi:
                return band_name
        return "verified" if score_val >= 0.8 else "unverified"

    def list_bands(self) -> list[dict]:
        """List all confidence bands and their ranges."""
        return [
            {"band": name, "min": lo, "max": hi}
            for name, (lo, hi) in CONFIDENCE_BANDS.items()
        ]

    def get_stats(self) -> dict[str, Any]:
        """Confidence engine statistics."""
        return {
            "factors": list(CONFIDENCE_FACTORS),
            "factor_count": len(CONFIDENCE_FACTORS),
            "bands": list(CONFIDENCE_BANDS.keys()),
            "band_count": len(CONFIDENCE_BANDS),
            "decay_half_life_days": DECAY_HALF_LIFE_DAYS,
        }

    def _compute_freshness(self, last_updated: float) -> float:
        """Exponential decay based on age."""
        age_days = (time.time() - last_updated) / 86400.0
        if age_days <= 0:
            return 1.0
        import math
        return math.exp(-0.693 * age_days / DECAY_HALF_LIFE_DAYS)
