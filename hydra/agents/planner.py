"""
AgentPlanner / AgentRouter / AgentIntelligence (Phase H).

Plans an ordered, advisory multi-agent workflow for a target, routes
Target → Agent → Capability → Tool (reusing the learning-driven ToolSelector), and
provides read-only orchestration analytics over the agents.

Strictly advisory + read-only: no tool execution, no finding confirmation, no wiki
writes, no confidence/promotion changes. Deterministic (planning/ownership are
now-independent; routing tool scores are deterministic given a fixed `now`).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from hydra.agents.registry import AgentRegistry
from hydra.capabilities.capability_catalog import CapabilityCatalog
from hydra.capabilities.source_learning import SourceLearningStore
from hydra.capabilities.tool_selection import ToolSelector
from hydra.knowledge.verification import VerificationLearningStore

# High-level target type → relevant capability categories (drives agent applicability).
TARGET_TYPE_CATEGORIES: Dict[str, List[str]] = {
    "web": ["reconnaissance", "web", "api", "infrastructure", "verification"],
    "api": ["reconnaissance", "api", "web", "infrastructure", "verification"],
    "cloud": ["reconnaissance", "cloud", "secrets", "source_code", "infrastructure", "verification"],
    "mobile": ["mobile", "secrets", "verification"],
    "network": ["reconnaissance", "infrastructure", "verification"],
    "code": ["source_code", "secrets", "verification"],
    "default": ["reconnaissance", "web", "api", "infrastructure", "verification"],
}


def _relevant_categories(target_type: str) -> set:
    return set(TARGET_TYPE_CATEGORIES.get(target_type, TARGET_TYPE_CATEGORIES["default"]))


@dataclass
class AgentStep:
    order: int
    agent_id: str
    priority: int
    knowledge_agent: bool
    assigned_capabilities: List[str]
    expected_value: float
    reasoning: str

    def to_dict(self) -> Dict:
        return {"order": self.order, "agent_id": self.agent_id, "priority": self.priority,
                "knowledge_agent": self.knowledge_agent,
                "assigned_capabilities": self.assigned_capabilities,
                "expected_value": self.expected_value, "reasoning": self.reasoning}


@dataclass
class AgentPlan:
    target: str
    target_type: str
    expected_value: float
    steps: List[AgentStep] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {"target": self.target, "target_type": self.target_type,
                "expected_value": self.expected_value,
                "steps": [s.to_dict() for s in self.steps]}


class AgentPlanner:
    def __init__(self, registry: Optional[AgentRegistry] = None,
                 catalog: Optional[CapabilityCatalog] = None):
        self.catalog = (catalog or CapabilityCatalog()).load()
        self.registry = (registry or AgentRegistry(capability_catalog=self.catalog)).load()

    def _assigned(self, agent, relevant: set) -> List:
        return sorted((c for c in agent.owned_capabilities(self.catalog) if c.category in relevant),
                      key=lambda c: (-c.confidence_weight, c.capability_id))

    def plan(self, target: str, target_type: str = "web", prior_findings: int = 0) -> AgentPlan:
        relevant = _relevant_categories(target_type)
        steps: List[AgentStep] = []
        order = 0
        for agent in self.registry.all():            # priority desc, deterministic
            if agent.knowledge_agent:
                # knowledge agents (correlation/reporting) always run, after recon/probe
                steps.append(AgentStep(
                    order=order, agent_id=agent.agent_id, priority=agent.priority,
                    knowledge_agent=True, assigned_capabilities=[],
                    expected_value=0.0,
                    reasoning=f"{agent.agent_id}: {agent.responsibilities}"))
                order += 1
                continue
            caps = self._assigned(agent, relevant)
            if not caps:
                continue                              # agent not relevant to this target type
            ev = round(sum(c.confidence_weight for c in caps) / len(caps), 4)
            steps.append(AgentStep(
                order=order, agent_id=agent.agent_id, priority=agent.priority,
                knowledge_agent=False,
                assigned_capabilities=[c.capability_id for c in caps],
                expected_value=ev,
                reasoning=f"{agent.agent_id}: {len(caps)} capabilities in "
                          f"{sorted({c.category for c in caps})}"))
            order += 1

        tool_steps = [s for s in steps if not s.knowledge_agent]
        if tool_steps:
            wsum = sum(1.0 / (i + 1) for i in range(len(tool_steps)))
            overall = round(sum(s.expected_value / (i + 1) for i, s in enumerate(tool_steps)) / wsum, 4)
        else:
            overall = 0.0
        return AgentPlan(target=target, target_type=target_type,
                         expected_value=overall, steps=steps)


class AgentRouter:
    """Deterministic Target → Agent → Capability → Tool routing (advisory)."""

    def __init__(self, registry: Optional[AgentRegistry] = None,
                 catalog: Optional[CapabilityCatalog] = None,
                 learning: Optional[SourceLearningStore] = None,
                 verification: Optional[VerificationLearningStore] = None,
                 now: Optional[float] = None):
        self.catalog = (catalog or CapabilityCatalog()).load()
        self.registry = (registry or AgentRegistry(capability_catalog=self.catalog)).load()
        self.selector = ToolSelector(self.catalog, learning, verification, now=now)
        self._planner = AgentPlanner(self.registry, self.catalog)

    def route(self, target: str, target_type: str = "web") -> Dict:
        plan = self._planner.plan(target, target_type)
        routes = []
        for step in plan.steps:
            cap_routes = []
            for cid in step.assigned_capabilities:
                best = self.selector.select(cid)
                cap_routes.append({"capability": cid,
                                   "tool": best.tool if best else None,
                                   "tool_score": best.score if best else None})
            routes.append({"agent_id": step.agent_id, "priority": step.priority,
                           "knowledge_agent": step.knowledge_agent,
                           "capabilities": cap_routes})
        return {"target": target, "target_type": target_type, "routes": routes}


class AgentIntelligence:
    """Read-only orchestration analytics over the agents + learning."""

    def __init__(self, registry: Optional[AgentRegistry] = None,
                 catalog: Optional[CapabilityCatalog] = None,
                 learning: Optional[SourceLearningStore] = None,
                 verification: Optional[VerificationLearningStore] = None):
        self.catalog = (catalog or CapabilityCatalog()).load()
        self.registry = (registry or AgentRegistry(capability_catalog=self.catalog)).load()
        self.learning = learning or SourceLearningStore()
        self.verification = verification or VerificationLearningStore()

    def _tool_events(self) -> Dict[str, int]:
        events: Dict[str, int] = {}
        for s in self.learning.all_scores():
            if s.source_id.startswith("source."):
                events[s.source_id[7:]] = events.get(s.source_id[7:], 0) + s.total_events
        for m in self.verification.method_stats():
            events[m["method"]] = events.get(m["method"], 0) + m["attempts"]
        return events

    def report(self) -> Dict:
        events = self._tool_events()
        agents = self.registry.all()
        all_caps = {c.capability_id for c in self.catalog.all()}

        ownership: Dict[str, List[str]] = {}
        agent_rows = []
        for a in agents:
            caps = a.owned_capabilities(self.catalog)
            cap_ids = [c.capability_id for c in caps]
            for cid in cap_ids:
                ownership.setdefault(cid, []).append(a.agent_id)
            tools = sorted({t for c in caps for t in c.tools})
            agent_events = sum(events.get(t, 0) for t in tools)
            mean_eff = round(agent_events / len(tools), 2) if tools else 0.0
            agent_rows.append({"agent_id": a.agent_id, "priority": a.priority,
                               "knowledge_agent": a.knowledge_agent,
                               "owned_capabilities": len(cap_ids), "tools": len(tools),
                               "total_events": agent_events, "mean_tool_events": mean_eff})

        owned = set(ownership)
        orphans = sorted(all_caps - owned)
        overlaps = {cid: ag for cid, ag in ownership.items() if len(ag) > 1}
        # bottlenecks: agents owning the most capabilities (single points of breadth)
        bottlenecks = sorted(agent_rows, key=lambda r: -r["owned_capabilities"])[:3]
        under_utilized = sorted(r["agent_id"] for r in agent_rows
                                if not r["knowledge_agent"] and r["total_events"] == 0)

        return {
            "agent_count": len(agents),
            "agent_effectiveness": sorted(agent_rows, key=lambda r: (-r["total_events"], r["agent_id"])),
            "capability_ownership": {
                "owned": len(owned), "total": len(all_caps),
                "orphan_capabilities": orphans, "overlaps": overlaps,
            },
            "workflow_coverage": {
                "covered": len(owned), "total": len(all_caps),
                "coverage_pct": round(100 * len(owned) / len(all_caps), 1) if all_caps else 0.0,
                "uncovered_categories": sorted({self.catalog.get(c).category for c in orphans}),
            },
            "bottlenecks": bottlenecks,
            "under_utilized_agents": under_utilized,
        }
