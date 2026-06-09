"""
CapabilityEffectivenessEngine (Phase P) — per-capability offensive effectiveness.

Computes, per capability, a deterministic blend of observed signals (health success rate +
verification rate) damped toward the static `confidence_weight` prior, plus utility (effectiveness
× breadth), contribution (effectiveness × dependency centrality), uniqueness and redundancy
(finding-type overlap with peers). Cold-start falls back to the prior (`status='prior_only'`).
Explainable (every term in `rationale`), deterministic, advisory only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

from hydra.offensive_intel.context import OffensiveContext
from hydra.offensive_intel.util import (
    blend_observed,
    damp_to_prior,
    jaccard,
    mean,
    norm,
)


@dataclass
class CapabilityEffectiveness:
    capability_id: str
    category: str
    effectiveness: float
    utility: float
    contribution: float
    uniqueness: float
    redundancy: float
    samples: int
    status: str                 # learned | prior_only
    verification_capable: bool
    finding_types: List[str]
    rationale: str

    def to_dict(self) -> Dict:
        return {
            "capability_id": self.capability_id, "category": self.category,
            "effectiveness": self.effectiveness, "utility": self.utility,
            "contribution": self.contribution, "uniqueness": self.uniqueness,
            "redundancy": self.redundancy, "samples": self.samples,
            "status": self.status, "verification_capable": self.verification_capable,
            "finding_types": self.finding_types, "rationale": self.rationale,
            "advisory": True,
        }


class CapabilityEffectivenessEngine:
    def __init__(self, ctx: Optional[OffensiveContext] = None):
        self.ctx = (ctx or OffensiveContext()).load()
        self._ranked: Optional[List[CapabilityEffectiveness]] = None
        self._map: Optional[Dict[str, CapabilityEffectiveness]] = None

    def _compute(self) -> List[CapabilityEffectiveness]:
        if self._ranked is not None:
            return self._ranked
        cat = self.ctx.catalog()
        caps = cat.all()
        finding_index: Dict[str, List[str]] = {}
        breadth: Dict[str, int] = {}
        for c in caps:
            breadth[c.capability_id] = len(c.supported_finding_types) + len(c.supported_target_types)
            for ft in c.supported_finding_types:
                finding_index.setdefault(ft, []).append(c.capability_id)
        max_breadth = max(breadth.values(), default=1) or 1
        degree: Dict[str, int] = {}
        for e in self.ctx.graph().edges():
            if e["relation"] in ("requires", "enhances"):
                degree[e["from"]] = degree.get(e["from"], 0) + 1
                degree[e["to"]] = degree.get(e["to"], 0) + 1
        max_degree = max(degree.values(), default=1) or 1

        out: List[CapabilityEffectiveness] = []
        for c in caps:
            cid = c.capability_id
            o = self.ctx.capability_outcome(cid)
            succ_rate = o.success_rate if o else None
            verif_rate, vatt = self.ctx.verification_for(c.supported_finding_types)
            samples = (o.decided if o else 0) + vatt
            observed = blend_observed(succ_rate, verif_rate)
            eff = damp_to_prior(c.confidence_weight, observed, samples)
            status = "learned" if (observed is not None and samples > 0) else "prior_only"
            peers = set()
            for ft in c.supported_finding_types:
                peers.update(finding_index.get(ft, []))
            peers.discard(cid)
            red = mean([jaccard(c.supported_finding_types, cat.get(p).supported_finding_types)
                        for p in sorted(peers)]) if peers else 0.0
            redundancy = round(red, 4)
            uniqueness = round(1.0 - redundancy, 4)
            utility = round(eff * norm(breadth[cid], max_breadth), 4)
            contribution = round(eff * (0.5 + 0.5 * norm(degree.get(cid, 0), max_degree)), 4)
            rationale = (
                f"prior={c.confidence_weight}; "
                f"observed={round(observed, 4) if observed is not None else 'n/a'}; "
                f"samples={samples}; status={status}")
            out.append(CapabilityEffectiveness(
                cid, c.category, eff, utility, contribution, uniqueness, redundancy,
                samples, status, c.is_verification, list(c.supported_finding_types), rationale))
        out.sort(key=lambda e: (-e.effectiveness, -e.contribution, e.capability_id))
        self._ranked = out
        self._map = {e.capability_id: e for e in out}
        return out

    # ── queries (deterministic) ──────────────────────────────────────────────────
    def rank(self, limit: Optional[int] = None) -> List[CapabilityEffectiveness]:
        r = self._compute()
        return r[:limit] if limit else r

    def as_map(self) -> Dict[str, CapabilityEffectiveness]:
        self._compute()
        return self._map or {}

    def get(self, capability_id: str) -> Optional[CapabilityEffectiveness]:
        return self.as_map().get(capability_id)

    def count(self) -> int:
        return len(self._compute())

    def top(self, n: int = 10) -> List[CapabilityEffectiveness]:
        return self._compute()[:max(1, n)]

    def weakest(self, n: int = 10) -> List[CapabilityEffectiveness]:
        return sorted(self._compute(),
                      key=lambda e: (e.effectiveness, e.capability_id))[:max(1, n)]

    def underutilized(self, n: int = 10) -> List[CapabilityEffectiveness]:
        """High-prior capabilities with no learned evidence yet (worth exercising)."""
        cand = [e for e in self._compute() if e.status == "prior_only"]
        cand.sort(key=lambda e: (-e.effectiveness, e.capability_id))
        return cand[:max(1, n)]
