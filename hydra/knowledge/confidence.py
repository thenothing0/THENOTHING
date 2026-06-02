"""
Confidence scoring engine — the Two-Signal rule, source weighting, and decay.

Pure functions (no I/O, no network) so the whole thing is trivially offline-testable.
Used by the recon-fusion pipeline (per-asset confidence) and by promotion (gating
high-confidence conclusions).

Rules (from the spec):
  * 1 independent source            -> low
  * 2 independent sources           -> medium
  * >= 3 independent sources        -> high
  Source `confidence_weight` can lift a 2-source asset to high when the combined
  weight is strong, but a single source can NEVER exceed low (Two-Signal rule).
  Confidence decays with age; contradictory evidence reduces it.
"""

from __future__ import annotations

import time
from typing import Dict, Iterable, List, Optional

from hydra.knowledge.schema import Confidence

# Default per-source weight when a source declares none.
_DEFAULT_WEIGHT = 0.4
# Age (seconds) beyond which a single decay step is applied. ~90 days.
DECAY_HORIZON_S = 90 * 24 * 3600


def score_from_sources(
    sources: Iterable[str],
    weights: Optional[Dict[str, float]] = None,
) -> Confidence:
    """Confidence for an asset/claim given the set of distinct sources that support it.

    `sources` are stable source ids; duplicates are collapsed (independence is by id).
    """
    weights = weights or {}
    distinct = sorted({s for s in sources if s})
    n = len(distinct)
    if n <= 0:
        return Confidence.LOW
    if n == 1:
        # Two-Signal rule: a single source can never be more than low.
        return Confidence.LOW
    if n >= 3:
        return Confidence.HIGH
    # Exactly two independent sources -> medium, unless combined weight is strong.
    combined = sum(weights.get(s, _DEFAULT_WEIGHT) for s in distinct)
    return Confidence.HIGH if combined >= 1.2 else Confidence.MEDIUM


def meets_two_signal(sources: Iterable[str]) -> bool:
    """True iff at least two independent signals support the claim."""
    return len({s for s in sources if s}) >= 2


def apply_decay(
    confidence: Confidence,
    last_reviewed_epoch: float,
    now: Optional[float] = None,
    horizon_s: float = DECAY_HORIZON_S,
) -> Confidence:
    """Age a confidence level. Each elapsed `horizon_s` drops it one notch (high->medium->low)."""
    now = now if now is not None else time.time()
    age = max(0.0, now - float(last_reviewed_epoch or now))
    steps = int(age // horizon_s)
    if steps <= 0:
        return confidence
    rank = max(0, confidence.rank - steps)
    return [Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH][rank]


def apply_contradiction(confidence: Confidence) -> Confidence:
    """Contradictory evidence must reduce confidence by one notch (never below low)."""
    rank = max(0, confidence.rank - 1)
    return [Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH][rank]


def aggregate_evidence(rows: List[Dict]) -> Dict[str, List[str]]:
    """Group raw (asset, source) rows into {asset: [distinct source ids...]} for scoring."""
    out: Dict[str, set] = {}
    for r in rows:
        asset = r.get("asset")
        src = r.get("source")
        if not asset or not src:
            continue
        out.setdefault(asset, set()).add(src)
    return {a: sorted(srcs) for a, srcs in out.items()}
