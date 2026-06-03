"""
Opportunity ranking + verification feedback (Phase D).

`OpportunityScore` is a **non-canonical** ranking signal. It combines, with fixed
declared weights:
  * confidence   — the band the *existing* confidence engine already assigned
                   (READ ONLY — confidence.py is never modified or recomputed here);
  * effectiveness— mean historical effectiveness of the recon sources behind the
                   candidate's evidence;
  * chain_potential — whether the opportunity is/feeds a multi-step chain;
  * novelty      — mean historical novelty of those sources;
  * evidence_diversity — distinct sources × distinct evidence classes.

The feedback loop (`record_outcome`) writes confirm/reject signals to the derived
`SourceLearningStore` ONLY. It never touches promotion rules, confidence, or the wiki.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from hydra.capabilities.source_learning import (
    EV_CHAIN,
    EV_CONFIRMED,
    EV_DISCOVERY,
    EV_DUPLICATE,
    EV_PATTERN,
    EV_REJECTED,
    OUTCOME_CONFIRMED,
    OUTCOME_REJECTED,
    SourceLearningStore,
)
from hydra.knowledge.discovery import ChainDiscovery, PatternDiscovery
from hydra.knowledge.schema import Confidence
from hydra.knowledge.wiki_store import WikiStore

# Declared weights — configuration for OPPORTUNITY ranking only. NOT confidence logic.
# (They sum to 1.0; the result is in [0, 1].)
OPPORTUNITY_WEIGHTS = {
    "confidence": 0.35,
    "effectiveness": 0.20,
    "chain_potential": 0.15,
    "novelty": 0.15,
    "evidence_diversity": 0.15,
}
_BAND_VALUE = {"low": 0.34, "medium": 0.67, "high": 1.0}
_DEFAULT_SOURCE_SCORE = 0.5  # neutral prior when a source has no history yet


@dataclass
class OpportunityScore:
    candidate_id: str
    candidate_type: str
    score: float
    components: Dict[str, float] = field(default_factory=dict)
    recommendation: str = ""
    source_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "candidate_id": self.candidate_id, "candidate_type": self.candidate_type,
            "score": self.score, "components": self.components,
            "recommendation": self.recommendation, "source_ids": self.source_ids,
        }


def _band_value(conf) -> float:
    return _BAND_VALUE.get(conf.value if isinstance(conf, Confidence) else conf, 0.34)


def candidate_source_ids(candidate, store: WikiStore) -> List[str]:
    """Recon source.ids behind a candidate's evidence (from evidence pages' `sources`
    frontmatter). Deterministic, de-duplicated. Empty when evidence carries no sources."""
    ids: set = set()
    for ev in getattr(candidate, "supporting_evidence", []):
        page = store.get(ev.ref)
        if page is None:
            continue
        for s in (page.meta.get("sources") or []):
            s = str(s).strip()
            if s.startswith("source."):
                ids.add(s)
    return sorted(ids)


class OpportunityScorer:
    def __init__(self, store: Optional[WikiStore] = None,
                 learning: Optional[SourceLearningStore] = None):
        self.store = store or WikiStore()
        self.learning = learning or SourceLearningStore()

    def score(self, candidate) -> OpportunityScore:
        src_ids = candidate_source_ids(candidate, self.store)
        scored = [self.learning.scores(s) for s in src_ids]

        conf_c = _band_value(candidate.confidence)
        eff_c = (sum(s.effectiveness_score for s in scored) / len(scored)
                 if scored else _DEFAULT_SOURCE_SCORE)
        nov_c = (sum(s.novelty_score for s in scored) / len(scored)
                 if scored else _DEFAULT_SOURCE_SCORE)
        chain_c = 1.0 if candidate.candidate_type == "chain" else 0.5
        distinct_classes = len({ev.evidence_class for ev in candidate.supporting_evidence})
        div_c = round(min(1.0, (len(src_ids) / 3.0) * 0.5 + (distinct_classes / 2.0) * 0.5), 4)

        components = {
            "confidence": round(conf_c, 4),
            "effectiveness": round(eff_c, 4),
            "chain_potential": round(chain_c, 4),
            "novelty": round(nov_c, 4),
            "evidence_diversity": div_c,
        }
        total = round(sum(OPPORTUNITY_WEIGHTS[k] * v for k, v in components.items()), 4)
        return OpportunityScore(
            candidate_id=candidate.id, candidate_type=candidate.candidate_type,
            score=total, components=components,
            recommendation=getattr(candidate, "recommendation", ""), source_ids=src_ids,
        )

    def rank(self, limit: int = 20) -> List[OpportunityScore]:
        candidates = (PatternDiscovery(self.store).discover()
                      + ChainDiscovery(self.store).discover())
        scored = [self.score(c) for c in candidates]
        # Deterministic: score desc, then candidate_id asc.
        scored.sort(key=lambda o: (-o.score, o.candidate_id))
        return scored[:limit]


# ── Verification feedback loop (writes ONLY to the derived learning store) ──────
def record_outcome(candidate_type: str, candidate_id: str, outcome: str,
                   store: Optional[WikiStore] = None,
                   learning: Optional[SourceLearningStore] = None) -> Dict:
    """Record a confirm/reject outcome as source-performance feedback.

    Resolves the candidate (re-running discovery), attributes the outcome to its
    contributing recon sources, and appends events to the learning store. Affects
    learning ONLY — promotion rules, confidence, and the wiki are never touched.
    """
    store = store or WikiStore()
    learning = learning or SourceLearningStore()
    ctype = candidate_type.strip().lower()
    outcome = outcome.strip().lower()
    if outcome not in (OUTCOME_CONFIRMED, OUTCOME_REJECTED):
        raise ValueError(f"outcome must be confirmed|rejected, got {outcome!r}")

    cands = (PatternDiscovery(store).discover() if ctype == "pattern"
             else ChainDiscovery(store).discover() if ctype == "chain" else [])
    match = next((c for c in cands if c.id == candidate_id), None)

    src_ids = candidate_source_ids(match, store) if match else []
    signature = getattr(match, "signature", "") if match else ""
    combo = sorted({ev.evidence_class for ev in match.supporting_evidence}) if match else []

    if outcome == OUTCOME_CONFIRMED:
        for sid in src_ids:
            learning.record_source_event(sid, EV_CONFIRMED)
            learning.record_source_event(sid, EV_PATTERN if ctype == "pattern" else EV_CHAIN)
    else:
        for sid in src_ids:
            learning.record_source_event(sid, EV_REJECTED)

    learning.record_outcome(ctype, candidate_id, outcome, signature=signature, evidence_combo=combo)
    return {"recorded": True, "candidate_type": ctype, "candidate_id": candidate_id,
            "outcome": outcome, "sources_credited": src_ids, "resolved": match is not None}


def record_fusion_discoveries(fusion_result, learning: Optional[SourceLearningStore] = None) -> int:
    """Credit a recon-fusion run to its sources (the discovery side of effectiveness).

    For each fused asset, every contributing source gets a `discovery` event; when an
    asset was corroborated by >1 source, the non-first sources also get a `duplicate`
    signal (they co-found rather than uniquely found). Derived/append-only; the wiki is
    untouched. Returns the number of discovery events recorded.
    """
    learning = learning or SourceLearningStore()
    n = 0
    for asset in getattr(fusion_result, "assets", []):
        srcs = [s for s in asset.sources if str(s).startswith("source.")]
        for i, sid in enumerate(srcs):
            learning.record_source_event(sid, EV_DISCOVERY)
            n += 1
            if len(srcs) > 1 and i > 0:
                learning.record_source_event(sid, EV_DUPLICATE)
    return n
