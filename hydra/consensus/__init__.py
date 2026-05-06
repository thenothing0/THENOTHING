"""
╔══════════════════════════════════════════════════════════════╗
║  Multi-Agent Consensus System — Voting & Confidence Fusion ║
║  Collaborative validation with quorum and disagreement     ║
╚══════════════════════════════════════════════════════════════╝
"""

import logging
import time
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger("hydra.consensus")


class VoteType(str, Enum):
    APPROVE = "approve"
    REJECT = "reject"
    ABSTAIN = "abstain"


@dataclass
class AgentVote:
    """A single agent's vote on a finding."""
    agent_id: str
    agent_type: str
    vote: VoteType
    confidence: float  # 0.0 - 1.0
    reasoning: str = ""
    timestamp: float = field(default_factory=time.time)


@dataclass
class ConsensusResult:
    """Result of consensus voting."""
    finding_id: str
    votes: List[AgentVote]
    final_decision: VoteType
    consensus_score: float
    agreement_level: float  # 0.0 (total disagreement) - 1.0 (unanimous)
    weighted_confidence: float
    quorum_met: bool
    contradictions: List[Dict[str, Any]]
    timestamp: float = field(default_factory=time.time)


# Agent type → weight in consensus
AGENT_WEIGHTS = {
    "validation": 1.5,
    "exploit_hypothesis": 1.2,
    "vuln_research": 1.0,
    "recon": 0.8,
    "reporting": 0.6,
}


class ConsensusEngine:
    """
    Multi-agent consensus system.
    
    Features:
      - Weighted voting by agent expertise
      - Confidence aggregation and fusion
      - Contradiction detection
      - Quorum system
      - Disagreement resolution
    """

    def __init__(self, quorum_size: int = 2,
                 approval_threshold: float = 0.6):
        self.quorum_size = quorum_size
        self.approval_threshold = approval_threshold
        self._pending_votes: Dict[str, List[AgentVote]] = {}
        self._results: Dict[str, ConsensusResult] = {}

    def submit_vote(self, finding_id: str, vote: AgentVote):
        """Submit a vote for a finding."""
        if finding_id not in self._pending_votes:
            self._pending_votes[finding_id] = []
        self._pending_votes[finding_id].append(vote)
        logger.debug(
            f"Vote received: {vote.agent_type} → {vote.vote.value} "
            f"(conf={vote.confidence:.2f}) for {finding_id}"
        )

    def evaluate(self, finding_id: str) -> Optional[ConsensusResult]:
        """Evaluate consensus for a finding."""
        votes = self._pending_votes.get(finding_id, [])
        if not votes:
            return None

        quorum_met = len(votes) >= self.quorum_size

        # Calculate weighted scores
        total_weight = 0.0
        approve_weight = 0.0
        reject_weight = 0.0

        for vote in votes:
            w = AGENT_WEIGHTS.get(vote.agent_type, 1.0)
            weight = w * vote.confidence
            total_weight += weight
            if vote.vote == VoteType.APPROVE:
                approve_weight += weight
            elif vote.vote == VoteType.REJECT:
                reject_weight += weight

        if total_weight == 0:
            total_weight = 1.0

        approval_ratio = approve_weight / total_weight

        # Decision
        if approval_ratio >= self.approval_threshold:
            decision = VoteType.APPROVE
        elif approval_ratio <= (1 - self.approval_threshold):
            decision = VoteType.REJECT
        else:
            decision = VoteType.ABSTAIN

        # Agreement level
        vote_types = [v.vote for v in votes if v.vote != VoteType.ABSTAIN]
        if vote_types:
            most_common = max(set(vote_types), key=vote_types.count)
            agreement = vote_types.count(most_common) / len(vote_types)
        else:
            agreement = 0.0

        # Weighted confidence
        weighted_conf = sum(
            v.confidence * AGENT_WEIGHTS.get(v.agent_type, 1.0)
            for v in votes
        ) / max(total_weight, 1.0)

        # Detect contradictions
        contradictions = self._detect_contradictions(votes)

        result = ConsensusResult(
            finding_id=finding_id, votes=votes,
            final_decision=decision,
            consensus_score=round(approval_ratio, 4),
            agreement_level=round(agreement, 4),
            weighted_confidence=round(weighted_conf, 4),
            quorum_met=quorum_met,
            contradictions=contradictions,
        )

        self._results[finding_id] = result
        return result

    def _detect_contradictions(
        self, votes: List[AgentVote]
    ) -> List[Dict[str, Any]]:
        """Detect contradicting votes between agents."""
        contradictions = []
        for i, v1 in enumerate(votes):
            for v2 in votes[i+1:]:
                if v1.vote != v2.vote and v1.vote != VoteType.ABSTAIN and v2.vote != VoteType.ABSTAIN:
                    if abs(v1.confidence - v2.confidence) < 0.3:
                        contradictions.append({
                            "agents": [v1.agent_type, v2.agent_type],
                            "votes": [v1.vote.value, v2.vote.value],
                            "confidences": [v1.confidence, v2.confidence],
                        })
        return contradictions

    def batch_evaluate(
        self, finding_ids: Optional[List[str]] = None
    ) -> Dict[str, ConsensusResult]:
        """Evaluate consensus for multiple findings."""
        ids = finding_ids or list(self._pending_votes.keys())
        results = {}
        for fid in ids:
            result = self.evaluate(fid)
            if result:
                results[fid] = result
        return results

    def get_result(self, finding_id: str) -> Optional[ConsensusResult]:
        return self._results.get(finding_id)

    def get_summary(self) -> Dict[str, Any]:
        total = len(self._results)
        approved = sum(
            1 for r in self._results.values()
            if r.final_decision == VoteType.APPROVE
        )
        rejected = sum(
            1 for r in self._results.values()
            if r.final_decision == VoteType.REJECT
        )
        return {
            "total_evaluated": total,
            "approved": approved,
            "rejected": rejected,
            "abstained": total - approved - rejected,
            "pending_votes": len(self._pending_votes),
            "avg_agreement": round(
                sum(r.agreement_level for r in self._results.values())
                / max(total, 1), 4
            ),
        }
