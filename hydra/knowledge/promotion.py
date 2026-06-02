"""
Knowledge promotion library — enforces the hierarchy and its hard rules.

    Observation -> Intel -> Hypothesis -> Finding -> Pattern -> Chain

Promotion is the only sanctioned way knowledge moves up a level. The rules are
NON-NEGOTIABLE (from the spec) and encoded here so no caller can bypass them:

  * No stage skipping (must promote to the immediate next stage).
  * Forbidden transitions raise regardless of evidence
    (Hypothesis->Pattern, Hypothesis->Chain, Observation->Finding, ...).
  * Every promotion needs supporting evidence.
  * Promotion to Finding/Pattern/Chain requires the Two-Signal rule
    (>= 2 independent signals).
  * Promotion to Finding requires in-scope (`scope_ok`); out-of-scope knowledge
    may remain Intel but must never become a Finding.

Pure logic + a thin page-mutation helper. Fully offline-testable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from hydra.knowledge.confidence import meets_two_signal
from hydra.knowledge.schema import (
    FORBIDDEN_PROMOTIONS,
    NODE_TYPE_FOR_STAGE,
    STAGE_ORDER,
    Stage,
)


class PromotionError(Exception):
    """Raised when a promotion violates the knowledge-hierarchy rules."""


@dataclass
class PromotionDecision:
    allowed: bool
    from_stage: Stage
    to_stage: Stage
    reason: str
    requires_two_signal: bool = False
    blockers: List[str] = field(default_factory=list)


_REQUIRE_TWO_SIGNAL = {Stage.FINDING, Stage.PATTERN, Stage.CHAIN}


def _next_stage(stage: Stage) -> Optional[Stage]:
    i = STAGE_ORDER.index(stage)
    return STAGE_ORDER[i + 1] if i + 1 < len(STAGE_ORDER) else None


def validate_promotion(
    from_stage: Stage,
    to_stage: Stage,
    sources: Optional[List[str]] = None,
    evidence_count: int = 0,
    scope_ok: bool = True,
) -> PromotionDecision:
    """Validate a promotion. Returns a decision; never raises (use `promote` to raise)."""
    sources = sources or []
    blockers: List[str] = []

    if (from_stage, to_stage) in FORBIDDEN_PROMOTIONS:
        blockers.append(f"forbidden transition {from_stage.value}->{to_stage.value} "
                        "(validation stages may not be skipped)")
    elif to_stage == from_stage:
        blockers.append("no-op: target stage equals current stage")
    elif STAGE_ORDER.index(to_stage) <= STAGE_ORDER.index(from_stage):
        blockers.append(f"downgrade/sideways {from_stage.value}->{to_stage.value} is not a promotion")
    elif to_stage != _next_stage(from_stage):
        blockers.append(f"stage skip {from_stage.value}->{to_stage.value} "
                        f"(must promote one step, to {_next_stage(from_stage).value if _next_stage(from_stage) else 'n/a'})")

    # Evidence is mandatory for every promotion.
    total_evidence = max(evidence_count, len(sources))
    if total_evidence < 1:
        blockers.append("no supporting evidence (every promotion requires evidence)")

    requires_two = to_stage in _REQUIRE_TWO_SIGNAL
    if requires_two and not (meets_two_signal(sources) or evidence_count >= 2):
        blockers.append(f"promotion to {to_stage.value} requires the Two-Signal rule "
                        "(>= 2 independent signals)")

    if to_stage == Stage.FINDING and not scope_ok:
        blockers.append("out-of-scope: may remain Intel but cannot become a Finding")

    return PromotionDecision(
        allowed=not blockers,
        from_stage=from_stage,
        to_stage=to_stage,
        reason="ok" if not blockers else "; ".join(blockers),
        requires_two_signal=requires_two,
        blockers=blockers,
    )


def promote(
    from_stage: Stage,
    to_stage: Stage,
    sources: Optional[List[str]] = None,
    evidence_count: int = 0,
    scope_ok: bool = True,
) -> PromotionDecision:
    """Validate and raise PromotionError if the promotion is illegal."""
    decision = validate_promotion(from_stage, to_stage, sources, evidence_count, scope_ok)
    if not decision.allowed:
        raise PromotionError(decision.reason)
    return decision


def apply_promotion(page, to_stage: Stage, sources=None, evidence_count: int = 0,
                    scope_ok: bool = True):
    """Promote a WikiPage in place after validation. Returns the (mutated) page.

    Raises PromotionError if illegal. `page.type`/`type` frontmatter is updated to the
    NodeType for the new stage; promotion never invents evidence.
    """
    from hydra.knowledge.schema import NodeType  # local import to avoid cycle at module load
    current = Stage(page.meta.get("stage") or _infer_stage(page))
    promote(current, to_stage, sources=sources, evidence_count=evidence_count, scope_ok=scope_ok)
    new_type: NodeType = NODE_TYPE_FOR_STAGE[to_stage]
    page.meta["type"] = new_type.value
    page.meta["stage"] = to_stage.value
    page.type = new_type
    return page


def _infer_stage(page) -> str:
    """Best-effort current stage from a page's type when no explicit `stage` is set."""
    t = (page.meta.get("type") or "").lower()
    mapping = {
        "observation": "observation", "intel": "intel", "hypothesis": "hypothesis",
        "finding": "finding", "pattern": "pattern", "chain": "chain",
    }
    return mapping.get(t, "observation")
