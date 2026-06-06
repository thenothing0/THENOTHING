"""
ConsensusEngine (Phase N) — advisory federation agreement scoring.

Given the per-peer effectiveness signals for a capability (gathered from imported digests),
it computes consensus confidence, a disagreement score, a diversity score, and a blended
federation confidence — plus a human-readable recommendation.

ADVISORY ONLY. It returns numbers and strings; it NEVER touches promotion.py, confidence.py,
the confidence bands, or any canonical/wiki state. Deterministic, read-only, O(E).
"""

from __future__ import annotations

from typing import Dict, List, Optional

from hydra.federation.intelligence import IntelligenceMesh
from hydra.federation.store import KnowledgeExchangeStore


def _mean(xs: List[float]) -> float:
    return sum(xs) / len(xs) if xs else 0.0


def _pstdev(xs: List[float]) -> float:
    if len(xs) < 2:
        return 0.0
    mu = _mean(xs)
    return (sum((x - mu) ** 2 for x in xs) / len(xs)) ** 0.5


class ConsensusEngine:
    def __init__(self, store: Optional[KnowledgeExchangeStore] = None,
                 mesh: Optional[IntelligenceMesh] = None):
        self.store = store or (mesh.store if mesh else KnowledgeExchangeStore())
        self.mesh = mesh or IntelligenceMesh(self.store)

    # Per-capability effectiveness samples across peers (one sample per peer-digest).
    def _samples(self) -> Dict[str, List[float]]:
        samples: Dict[str, List[float]] = {}
        for env in self.store.imported_digests():
            for cd in env.get("capability_digests", []):
                cid = cd.get("capability_id")
                eff = float(cd.get("effectiveness", 0.0) or 0.0)
                if cid and eff > 0:
                    samples.setdefault(cid, []).append(eff)
        return samples

    def _total_peers(self) -> int:
        return len({env.get("origin_peer_id", "") for env in self.store.imported_digests()})

    @staticmethod
    def _recommend(conf: float, disagreement: float, diversity: float) -> str:
        if diversity < 0.34:
            return "insufficient_diversity: too few independent peers for consensus"
        if disagreement >= 0.25:
            return "contested: peers disagree — treat as a weak federation signal"
        if conf >= 0.66:
            return "strong_consensus: capability is broadly effective across the federation"
        if conf >= 0.4:
            return "moderate_consensus: capability shows consistent moderate effectiveness"
        return "low_consensus: capability is consistently low-yield across peers"

    def capability_consensus(self, capability_id: str) -> Dict:
        xs = self._samples().get(capability_id, [])
        total_peers = max(1, self._total_peers())
        consensus_confidence = round(_mean(xs), 4)
        disagreement = round(_pstdev(xs), 4)
        diversity = round(len(xs) / total_peers, 4)
        federation_confidence = round(
            consensus_confidence * (1.0 - min(1.0, disagreement)) * min(1.0, diversity), 4)
        return {
            "capability_id": capability_id,
            "peer_samples": len(xs),
            "consensus_confidence": consensus_confidence,
            "disagreement_score": disagreement,
            "diversity_score": diversity,
            "federation_confidence": federation_confidence,
            "recommendation": self._recommend(consensus_confidence, disagreement, diversity),
            "advisory": True,
        }

    def consensus_report(self, top: int = 20) -> Dict:
        samples = self._samples()
        rows = [self.capability_consensus(cid) for cid in sorted(samples)]
        rows.sort(key=lambda d: (-d["federation_confidence"], d["capability_id"]))
        fed = [r["federation_confidence"] for r in rows]
        return {
            "capabilities_evaluated": len(rows),
            "mean_federation_confidence": round(_mean(fed), 4),
            "top_consensus": rows[:top],
            "advisory": True,
            "note": "advisory only — never influences promotion or confidence bands",
        }
