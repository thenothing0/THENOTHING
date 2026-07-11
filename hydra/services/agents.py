"""Agent Ecosystem Service — specialized AI agents exposed as services.

Wraps the agent swarm (BaseAgent, CoordinatorAgent, AgentFactory) into
a service layer with task management, agent lifecycle, and status tracking.
"""

import logging
from typing import Any

from hydra.services.base import BaseService

logger = logging.getLogger("hydra.services.agents")

AGENT_TYPES = (
    "recon", "vuln_research", "exploit", "report_writer",
    "api_analyzer", "cloud_scanner", "web3_auditor",
    "code_reviewer", "osint", "coordinator",
)


class AgentService(BaseService):
    """Agent ecosystem management and task dispatch."""

    def list_agents(self) -> list[dict]:
        """List available agent types and their capabilities."""
        agents = []
        for agent_type in AGENT_TYPES:
            agents.append({
                "type": agent_type,
                "available": True,
                "description": self._agent_description(agent_type),
            })
        return agents

    def spawn_agent(self, agent_type: str, task: dict) -> dict:
        """Spawn a specialized agent for a task."""
        if agent_type not in AGENT_TYPES:
            return {"status": "error",
                    "error": f"Unknown agent type: {agent_type}"}
        try:
            from hydra.swarm.agent_factory import AgentFactory
            factory = AgentFactory(self._bus)
            agent = factory.spawn_specialized_agent(agent_type)
            self._emit("agent.spawned", {
                "agent_type": agent_type,
                "task_id": task.get("id", ""),
            })
            return {
                "status": "spawned",
                "agent_type": agent_type,
                "task_id": task.get("id", ""),
            }
        except (ImportError, Exception):
            return self._simulate_spawn(agent_type, task)

    def execute_task(self, agent_type: str, task_payload: dict) -> dict:
        """Execute a task with a specific agent type."""
        try:
            from hydra.swarm.agent_factory import AgentFactory

            factory = AgentFactory(self._bus)
            agent = factory.spawn_specialized_agent(agent_type)
            if agent is None:
                return {"status": "error", "error": f"Failed to spawn {agent_type}"}

            result = agent.execute(task_payload)
            self._emit("agent.task_completed", {
                "agent_type": agent_type,
                "status": "completed",
            })
            return {
                "status": "completed",
                "agent_type": agent_type,
                "result": result,
            }
        except (ImportError, Exception):
            return self._simulate_execute(agent_type, task_payload)

    def detect_target_type(self, target: str) -> dict:
        """Detect what type of target this is and suggest agents."""
        try:
            from hydra.swarm.agent_factory import AgentFactory
            factory = AgentFactory(self._bus)
            target_type = factory.detect_target_type(target)
            hints = factory.get_workflow_hints(target_type)
            return {
                "target": target,
                "target_type": target_type,
                "suggested_agents": hints.get("agents", []),
                "workflow": hints.get("workflow", ""),
            }
        except (ImportError, Exception):
            return self._fallback_detect(target)

    def get_coordinator_status(self) -> dict:
        """Get the coordinator agent's current status."""
        try:
            from hydra.swarm.coordinator import CoordinatorAgent
            coord = CoordinatorAgent()
            return coord.get_scan_status()
        except (ImportError, Exception):
            return {"status": "idle", "active_agents": 0, "phase": "none"}

    def get_stats(self) -> dict[str, Any]:
        """Agent ecosystem statistics."""
        return {
            "available_types": list(AGENT_TYPES),
            "type_count": len(AGENT_TYPES),
        }

    def _simulate_spawn(self, agent_type: str, task: dict) -> dict:
        self._emit("agent.spawned", {
            "agent_type": agent_type,
            "task_id": task.get("id", ""),
            "simulated": True,
        })
        return {
            "status": "spawned",
            "agent_type": agent_type,
            "task_id": task.get("id", ""),
            "simulated": True,
        }

    def _simulate_execute(self, agent_type: str, task_payload: dict) -> dict:
        self._emit("agent.task_completed", {
            "agent_type": agent_type, "simulated": True,
        })
        return {
            "status": "completed",
            "agent_type": agent_type,
            "simulated": True,
        }

    def _fallback_detect(self, target: str) -> dict:
        lower = target.lower()
        if any(k in lower for k in ("api.", "/api/", "/v1/", "/v2/", "graphql")):
            ttype = "api"
        elif any(k in lower for k in (".sol", "0x", "contract", "web3")):
            ttype = "web3"
        elif any(k in lower for k in ("aws.", "gcp.", "azure.", "cloud")):
            ttype = "cloud"
        elif any(k in lower for k in (".apk", "play.google", "apps.apple")):
            ttype = "mobile"
        else:
            ttype = "web"
        agent_map = {
            "api": ["recon", "api_analyzer", "vuln_research"],
            "web3": ["recon", "web3_auditor", "vuln_research"],
            "cloud": ["recon", "cloud_scanner", "vuln_research"],
            "mobile": ["recon", "vuln_research"],
            "web": ["recon", "vuln_research", "exploit"],
        }
        return {
            "target": target,
            "target_type": ttype,
            "suggested_agents": agent_map.get(ttype, ["recon"]),
            "workflow": f"{ttype}_assessment",
        }

    def _agent_description(self, agent_type: str) -> str:
        descriptions = {
            "recon": "Subdomain enumeration, port scanning, tech fingerprinting",
            "vuln_research": "Vulnerability hypothesis generation and validation",
            "exploit": "PoC development and exploitation chain building",
            "report_writer": "Finding documentation and report generation",
            "api_analyzer": "API endpoint discovery and auth testing",
            "cloud_scanner": "Cloud misconfiguration and IAM analysis",
            "web3_auditor": "Smart contract and DeFi protocol auditing",
            "code_reviewer": "Source code security review",
            "osint": "Open source intelligence gathering",
            "coordinator": "Multi-agent orchestration and task dispatch",
        }
        return descriptions.get(agent_type, "Specialized security agent")
