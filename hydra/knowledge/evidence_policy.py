"""
evidence_policy — CONFIGURATION ONLY (Phase C).

This module declares how strongly each *class* of discovery evidence counts. It is
deliberately **data, not logic**: a class→weight table plus a trivial lookup. It
contains NO scoring math, NO thresholds, NO banding, NO decay — and it must never
grow into a second confidence engine. All confidence computation
(`score_from_sources`, `meets_two_signal`, decay, contradiction) stays owned
*exclusively* by `hydra.knowledge.confidence`.

Phase-C discovery classifies each piece of supporting evidence, resolves its weight
here, and hands the (ref → weight) map straight to
`confidence.score_from_sources(...)`. That keeps the weighting auditable and free of
magic constants embedded in discovery logic, while the actual math lives in one place.

Locked decision: validated findings outweigh report-derived intel; hypotheses
contribute zero and can never satisfy a threshold.
"""

from __future__ import annotations

from typing import Dict

# Evidence classes recognised by discovery.
CLASS_VALIDATED_FINDING = "validated_finding"
CLASS_REPORT_INTEL = "report_intel"
CLASS_HYPOTHESIS = "hypothesis"

# The single declarative table. Tuning Phase-C evidence weighting = editing this dict.
# Weights are chosen to compose with the EXISTING confidence engine's two-source rule
# (combined weight >= 1.2 ⇒ high): two findings (0.7+0.7=1.4) → high; a finding plus
# report-intel (0.7+0.4=1.1) → medium; hypotheses (0.0) are dropped before scoring.
EVIDENCE_WEIGHTS: Dict[str, float] = {
    CLASS_VALIDATED_FINDING: 0.7,
    CLASS_REPORT_INTEL: 0.4,
    CLASS_HYPOTHESIS: 0.0,
}

# Classes that never count toward a pattern/chain threshold (weight 0 ⇒ excluded).
EXCLUDED_CLASSES = frozenset({CLASS_HYPOTHESIS})


def weight_for(evidence_class: str) -> float:
    """Pure table lookup. Unknown classes default to 0.0 (excluded), never inflated."""
    return EVIDENCE_WEIGHTS.get(evidence_class, 0.0)


def is_excluded(evidence_class: str) -> bool:
    """True if this evidence class must not contribute to a threshold (e.g. hypothesis)."""
    return evidence_class in EXCLUDED_CLASSES or weight_for(evidence_class) <= 0.0
