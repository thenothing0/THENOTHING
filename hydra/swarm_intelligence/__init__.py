"""
╔══════════════════════════════════════════════════════════════╗
║  Collaborative Swarm Intelligence — Multi-Agent Reasoning    ║
║  Agent pairing, distributed hypothesis testing, consensus    ║
║  formation, parallel exploration, resource sharing           ║
╚══════════════════════════════════════════════════════════════╝
"""

import asyncio
import logging
import time
import uuid
from enum import Enum
from typing import Any, Callable, Dict, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger("hydra.swarm_intelligence")


class SwarmRole(str, Enum):
    EXPLORER = "explorer"         # Broad recon, surface enumeration
    ANALYST = "analyst"           # Deep analysis, pattern recognition
    HUNTER = "hunter"             # Targeted exploitation, hypothesis testing
    VALIDATOR = "validator"       # Evidence verification, reproduction
    COORDINATOR = "coordinator"   # Task routing, conflict resolution


class TaskPriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    NORMAL = "normal"
    LOW = "low"
    BACKGROUND = "background"


@dataclass
class SwarmAgent:
    """A swarm agent with role and capabilities."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str = ""
    role: SwarmRole = SwarmRole.EXPLORER
    capabilities: List[str] = field(default_factory=list)
    current_task: Optional[str] = None
    findings: List[Dict[str, Any]] = field(default_factory=list)
    status: str = "idle"          # idle, working, paused, completed
    partner_id: Optional[str] = None
    total_tasks: int = 0
    successful_tasks: int = 0


@dataclass
class SwarmTask:
    """A task for the swarm."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    description: str = ""
    task_type: str = ""
    priority: TaskPriority = TaskPriority.NORMAL
    assigned_to: List[str] = field(default_factory=list)
    status: str = "pending"
    result: Optional[Dict[str, Any]] = None
    created_at: float = field(default_factory=time.time)
    completed_at: float = 0.0


@dataclass
class SwarmConsensus:
    """A consensus decision from the swarm."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    topic: str = ""
    votes: Dict[str, str] = field(default_factory=dict)      # agent_id → vote
    reasoning: Dict[str, str] = field(default_factory=dict)   # agent_id → reasoning
    decision: str = ""
    confidence: float = 0.0
    timestamp: float = field(default_factory=time.time)


class CollaborativeSwarm:
    """
    Multi-agent collaborative swarm intelligence system.

    Enables:
      - Agent pairing (explorer+analyst, hunter+validator)
      - Distributed hypothesis testing across agents
      - Consensus formation for critical decisions
      - Parallel exploration of different attack vectors
      - Resource sharing between agents
      - Conflict resolution via voting

    Swarm behaviors:
      - EXPLORE: Broad surface expansion
      - CONVERGE: Focus on high-value targets
      - VERIFY: Independent validation of findings
      - DEBATE: Multi-agent adversarial reasoning
    """

    def __init__(self):
        self._agents: Dict[str, SwarmAgent] = {}
        self._tasks: Dict[str, SwarmTask] = {}
        self._consensuses: List[SwarmConsensus] = []
        self._shared_findings: List[Dict[str, Any]] = []
        self._task_queue: List[str] = []

    # ── Agent Management ──────────────────────

    def register_agent(self, agent: SwarmAgent) -> str:
        self._agents[agent.id] = agent
        logger.debug(f"Agent registered: {agent.name} ({agent.role.value})")
        return agent.id

    def create_agent(self, name: str, role: SwarmRole,
                      capabilities: List[str] = None) -> SwarmAgent:
        agent = SwarmAgent(name=name, role=role,
                            capabilities=capabilities or [])
        self.register_agent(agent)
        return agent

    def pair_agents(self, agent_a_id: str, agent_b_id: str):
        """Pair two agents for collaborative work."""
        a = self._agents.get(agent_a_id)
        b = self._agents.get(agent_b_id)
        if a and b:
            a.partner_id = agent_b_id
            b.partner_id = agent_a_id
            logger.info(f"🤝 Paired: {a.name} ({a.role.value}) ↔ {b.name} ({b.role.value})")

    def auto_pair(self) -> List[tuple]:
        """Auto-pair agents based on complementary roles."""
        pairs = []
        pairing_rules = {
            SwarmRole.EXPLORER: SwarmRole.ANALYST,
            SwarmRole.HUNTER: SwarmRole.VALIDATOR,
        }
        unpaired = [a for a in self._agents.values() if not a.partner_id]
        for agent in unpaired:
            preferred = pairing_rules.get(agent.role)
            if preferred:
                partner = next(
                    (a for a in unpaired if a.role == preferred
                     and not a.partner_id and a.id != agent.id),
                    None
                )
                if partner:
                    self.pair_agents(agent.id, partner.id)
                    pairs.append((agent.id, partner.id))
        return pairs

    # ── Task Distribution ─────────────────────

    def create_task(self, description: str, task_type: str,
                     priority: TaskPriority = TaskPriority.NORMAL) -> SwarmTask:
        task = SwarmTask(description=description, task_type=task_type,
                          priority=priority)
        self._tasks[task.id] = task
        self._task_queue.append(task.id)
        return task

    def assign_task(self, task_id: str, agent_id: str):
        task = self._tasks.get(task_id)
        agent = self._agents.get(agent_id)
        if task and agent:
            task.assigned_to.append(agent_id)
            task.status = "assigned"
            agent.current_task = task_id
            agent.status = "working"

    def distribute_tasks(self):
        """Distribute pending tasks to available agents."""
        # Sort by priority
        pending = [self._tasks[tid] for tid in self._task_queue
                    if self._tasks.get(tid, SwarmTask()).status == "pending"]
        pending.sort(key=lambda t: list(TaskPriority).index(t.priority))

        idle = [a for a in self._agents.values() if a.status == "idle"]

        for task in pending:
            # Find best agent for task
            best = self._find_best_agent(task, idle)
            if best:
                self.assign_task(task.id, best.id)
                idle.remove(best)

    def _find_best_agent(self, task: SwarmTask,
                          available: List[SwarmAgent]) -> Optional[SwarmAgent]:
        """Find the best agent for a task based on role and capabilities."""
        # Map task types to preferred roles
        role_map = {
            "recon": SwarmRole.EXPLORER,
            "analysis": SwarmRole.ANALYST,
            "exploit": SwarmRole.HUNTER,
            "validate": SwarmRole.VALIDATOR,
        }
        preferred_role = role_map.get(task.task_type, SwarmRole.EXPLORER)

        # Try preferred role first
        for agent in available:
            if agent.role == preferred_role:
                return agent

        # Fallback to any available
        return available[0] if available else None

    def complete_task(self, task_id: str, result: Dict[str, Any]):
        """Mark a task as completed with results."""
        task = self._tasks.get(task_id)
        if not task:
            return
        task.status = "completed"
        task.result = result
        task.completed_at = time.time()

        # Update agent stats
        for aid in task.assigned_to:
            agent = self._agents.get(aid)
            if agent:
                agent.current_task = None
                agent.status = "idle"
                agent.total_tasks += 1
                if result.get("success"):
                    agent.successful_tasks += 1

        # Share findings
        if result.get("findings"):
            self._shared_findings.extend(result["findings"])

    # ── Consensus Formation ───────────────────

    def initiate_consensus(self, topic: str,
                            options: List[str]) -> SwarmConsensus:
        """Initiate a consensus vote among agents."""
        consensus = SwarmConsensus(topic=topic)
        self._consensuses.append(consensus)
        return consensus

    def cast_vote(self, consensus_id: str, agent_id: str,
                   vote: str, reasoning: str = ""):
        """Cast a vote in a consensus decision."""
        for c in self._consensuses:
            if c.id == consensus_id:
                c.votes[agent_id] = vote
                c.reasoning[agent_id] = reasoning
                break

    def resolve_consensus(self, consensus_id: str) -> Optional[SwarmConsensus]:
        """Resolve a consensus by majority vote."""
        for c in self._consensuses:
            if c.id == consensus_id:
                if not c.votes:
                    return c
                # Count votes
                vote_counts: Dict[str, int] = {}
                for vote in c.votes.values():
                    vote_counts[vote] = vote_counts.get(vote, 0) + 1
                # Winner
                winner = max(vote_counts, key=vote_counts.get)
                c.decision = winner
                c.confidence = vote_counts[winner] / len(c.votes)
                return c
        return None

    # ── Shared Intelligence ───────────────────

    def share_finding(self, agent_id: str, finding: Dict[str, Any]):
        """Share a finding with the swarm."""
        finding["shared_by"] = agent_id
        finding["shared_at"] = time.time()
        self._shared_findings.append(finding)

    def get_shared_findings(self, since: float = 0) -> List[Dict[str, Any]]:
        """Get findings shared since a timestamp."""
        return [f for f in self._shared_findings
                if f.get("shared_at", 0) > since]

    # ── Summary ───────────────────────────────

    def get_summary(self) -> Dict[str, Any]:
        by_role = {}
        for a in self._agents.values():
            by_role[a.role.value] = by_role.get(a.role.value, 0) + 1
        tasks_completed = sum(1 for t in self._tasks.values() if t.status == "completed")
        return {
            "total_agents": len(self._agents),
            "by_role": by_role,
            "total_tasks": len(self._tasks),
            "completed_tasks": tasks_completed,
            "shared_findings": len(self._shared_findings),
            "consensuses": len(self._consensuses),
        }
