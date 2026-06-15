"""
OpportunityRanker (Phase S) — the versioned OpportunityScore engine.

Scores each capability as an OFFENSIVE OPPORTUNITY: where the highest-value, least-covered,
most-leveraged reach is. The score is a deterministic, fully-explainable weighted blend of bounded
components plus two small capped cross-layer bonuses:

    score = clamp01( W_VALUE   * value            # Phase-P utility (effectiveness × breadth)
                   + W_DEFICIT * coverage_deficit  # how under-covered the capability is now
                   + W_CHAIN   * chain_potential    # Phase-P dependency contribution/centrality
                   + W_UNIQUE  * uniqueness          # Phase-P (1 - redundancy)
                   + W_NOVELTY * novelty             # never-exercised (prior-only) capability
                   + temporal_bonus                  # Phase-O emerging (capped)
                   + federation_bonus )              # Phase-N demand across peers (capped)

The five weights sum to 1.0; the bonuses are capped — so a high score means "valuable AND
under-exploited", the classic definition of an opportunity. Versioned (OPPORTUNITY_SCORING_VERSION)
and explainable (every term in `components`). Deterministic, read-only, advisory; NON-executing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

from hydra.opportunity_intel.context import OpportunityContext
from hydra.opportunity_intel.util import (
    FEDERATION_BONUS_CAP,
    FEDERATION_PER_PEER,
    OPPORTUNITY_SCORING_VERSION,
    TEMPORAL_BONUS_CAP,
    W_CHAIN,
    W_DEFICIT,
    W_NOVELTY,
    W_UNIQUE,
    W_VALUE,
    clamp01,
    mean,
)


@dataclass
class Opportunity:
    opportunity_id: str            # == capability_id
    category: str
    score: float
    value: float
    coverage_deficit: float
    chain_potential: float
    uniqueness: float
    novelty: float
    temporal_bonus: float
    federation_demand: int
    status: str                    # learned | prior_only
    components: Dict[str, float]
    rationale: str

    def to_dict(self) -> Dict:
        return {
            "opportunity_id": self.opportunity_id, "capability_id": self.opportunity_id,
            "category": self.category, "score": self.score, "value": self.value,
            "coverage_deficit": self.coverage_deficit, "chain_potential": self.chain_potential,
            "uniqueness": self.uniqueness, "novelty": self.novelty,
            "temporal_bonus": self.temporal_bonus, "federation_demand": self.federation_demand,
            "status": self.status, "components": self.components, "rationale": self.rationale,
            "scoring_version": OPPORTUNITY_SCORING_VERSION, "advisory": True,
        }


class OpportunityRanker:
    def __init__(self, oc: Optional[OpportunityContext] = None):
        self.oc = oc or OpportunityContext()
        self._ranked: Optional[List[Opportunity]] = None
        self._map: Optional[Dict[str, Opportunity]] = None

    def _verification_blind_categories(self) -> set:
        return {c["category"] for c in self.oc.oi.coverage.category_coverage()
                if c["verification_coverage_pct"] == 0.0}

    def _compute(self) -> List[Opportunity]:
        if self._ranked is not None:
            return self._ranked
        cat = self.oc.catalog()
        emap = self.oc.eff_map()
        owner = self.oc.owner_of()
        cap_to_skills = self.oc.cap_to_skills()
        emerging = self.oc.temporal_signal()["emerging"]
        demand = self.oc.federation_signal()
        verif_blind = self._verification_blind_categories()

        out: List[Opportunity] = []
        for c in cat.all():
            cid = c.capability_id
            ce = emap.get(cid)
            value = ce.utility if ce else 0.0
            chain = ce.contribution if ce else 0.0
            uniqueness = ce.uniqueness if ce else 0.0
            status = ce.status if ce else "prior_only"

            o = self.oc.ctx.capability_outcome(cid)
            not_exercised = 1.0 if not (o and o.events > 0) else 0.0
            no_skill = 1.0 if not cap_to_skills.get(cid) else 0.0
            no_owner = 1.0 if not owner.get(cid) else 0.0
            verification_blind = 1.0 if c.category in verif_blind else 0.0
            coverage_deficit = round(mean([not_exercised, no_skill, no_owner,
                                           verification_blind]), 4)

            novelty = 1.0 if status == "prior_only" else 0.0
            temporal_bonus = TEMPORAL_BONUS_CAP if cid in emerging else 0.0
            peers = demand.get(cid, 0)
            federation_bonus = min(FEDERATION_BONUS_CAP, FEDERATION_PER_PEER * peers)

            base = (W_VALUE * value + W_DEFICIT * coverage_deficit + W_CHAIN * chain
                    + W_UNIQUE * uniqueness + W_NOVELTY * novelty)
            score = round(clamp01(base + temporal_bonus + federation_bonus), 4)
            components = {
                "value": round(W_VALUE * value, 4),
                "coverage_deficit": round(W_DEFICIT * coverage_deficit, 4),
                "chain_potential": round(W_CHAIN * chain, 4),
                "uniqueness": round(W_UNIQUE * uniqueness, 4),
                "novelty": round(W_NOVELTY * novelty, 4),
                "temporal_bonus": round(temporal_bonus, 4),
                "federation_bonus": round(federation_bonus, 4),
            }
            rationale = (f"value={round(value, 4)}; deficit={coverage_deficit} "
                         f"(exercise/skill/owner/verify); chain={round(chain, 4)}; "
                         f"unique={round(uniqueness, 4)}; novelty={novelty}; "
                         f"status={status}; peers={peers}")
            out.append(Opportunity(
                cid, c.category, score, round(value, 4), coverage_deficit, round(chain, 4),
                round(uniqueness, 4), novelty, round(temporal_bonus, 4), peers, status,
                components, rationale))
        out.sort(key=lambda e: (-e.score, -e.coverage_deficit, e.opportunity_id))
        self._ranked = out
        self._map = {e.opportunity_id: e for e in out}
        return out

    # ── queries (deterministic) ──────────────────────────────────────────────────
    def rank(self, limit: Optional[int] = None) -> List[Opportunity]:
        r = self._compute()
        return r[:limit] if limit else r

    def get(self, capability_id: str) -> Optional[Opportunity]:
        self._compute()
        return (self._map or {}).get(capability_id)

    def by_category(self) -> List[Dict]:
        rows: Dict[str, List[float]] = {}
        for o in self._compute():
            rows.setdefault(o.category, []).append(o.score)
        out = [{"category": k, "opportunities": len(v),
                "mean_score": round(mean(v), 4), "max_score": round(max(v), 4)}
               for k, v in rows.items()]
        out.sort(key=lambda d: (-d["mean_score"], d["category"]))
        return out

    def report(self, limit: int = 25) -> Dict:
        ranked = self._compute()
        return {
            "opportunities": [o.to_dict() for o in ranked[:max(1, limit)]],
            "count": len(ranked),
            "top": [o.opportunity_id for o in ranked[:5]],
            "by_category": self.by_category(),
            "scoring_version": OPPORTUNITY_SCORING_VERSION, "advisory": True,
        }
