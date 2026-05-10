"""Tests for the Consensus Engine."""

import pytest
from hydra.consensus import ConsensusEngine, AgentVote, VoteType


class TestConsensusEngine:
    """Test multi-agent consensus voting."""

    def test_engine_creation(self):
        engine = ConsensusEngine()
        assert engine is not None

    def test_submit_vote(self):
        engine = ConsensusEngine()
        vote = AgentVote(
            agent_id="recon-1",
            agent_type="recon",
            vote=VoteType.APPROVE,
            confidence=0.9,
        )
        engine.submit_vote(finding_id="f1", vote=vote)
        votes = engine._pending_votes.get("f1", [])
        assert len(votes) == 1

    def test_consensus_reached_with_quorum(self):
        engine = ConsensusEngine()
        for i in range(3):
            vote = AgentVote(
                agent_id=f"agent-{i}",
                agent_type="vuln_research",
                vote=VoteType.APPROVE,
                confidence=0.85,
            )
            engine.submit_vote(finding_id="f2", vote=vote)
        result = engine.evaluate("f2")
        assert result is not None
        assert result.final_decision == VoteType.APPROVE
        assert result.quorum_met is True

    def test_contradiction_detection(self):
        engine = ConsensusEngine()
        engine.submit_vote("f3", AgentVote("a1", "recon", VoteType.APPROVE, 0.9))
        engine.submit_vote("f3", AgentVote("a2", "validation", VoteType.REJECT, 0.8))
        result = engine.evaluate("f3")
        assert result is not None
        assert len(result.contradictions) > 0

    def test_confidence_fusion(self):
        engine = ConsensusEngine()
        engine.submit_vote("f4", AgentVote("a1", "recon", VoteType.APPROVE, 0.7))
        engine.submit_vote("f4", AgentVote("a2", "vuln_research", VoteType.APPROVE, 0.9))
        engine.submit_vote("f4", AgentVote("a3", "validation", VoteType.APPROVE, 0.85))
        result = engine.evaluate("f4")
        assert result is not None
        assert 0.7 <= result.weighted_confidence <= 1.0
