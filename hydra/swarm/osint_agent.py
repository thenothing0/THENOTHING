"""
╔══════════════════════════════════════════════════════════════╗
║  OSINT Intelligence Agent — Swarm Agent for OSINT tasks     ║
║  Passive recon, infrastructure attribution, leak analysis    ║
╚══════════════════════════════════════════════════════════════╝
"""

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional

from hydra.swarm.base_agent import BaseAgent
from hydra.memory.bus import MemoryBus, Task

logger = logging.getLogger("hydra.swarm.osint")


class OSINTAgent(BaseAgent):
    """
    OSINT Intelligence Agent.

    Responsibilities:
      - Passive reconnaissance
      - Infrastructure attribution
      - Organization mapping
      - Cloud exposure discovery
      - Public leak analysis
      - Attack surface enrichment

    Stateless — all results flow through MemoryBus.
    """

    AGENT_TYPE = "osint"
    AGENT_NAME = "OSINT Intelligence Agent"

    def __init__(self, bus: MemoryBus, osint_engine=None,
                 github_intel=None, agent_id: Optional[str] = None):
        super().__init__(bus, agent_id)
        self._osint_engine = osint_engine
        self._github_intel = github_intel

    def set_osint_engine(self, engine):
        self._osint_engine = engine

    def set_github_intel(self, github_intel):
        self._github_intel = github_intel

    async def execute(self, task: Task) -> Dict[str, Any]:
        """Execute an OSINT task."""
        target = task.payload.get("target", "")
        task_type = task.task_type

        self.logger.info(f"🔍 OSINT task: {task_type} → {target}")

        handlers = {
            "full_osint": self._run_full_osint,
            "cert_transparency": self._run_cert_transparency,
            "dns_intelligence": self._run_dns_intel,
            "wayback_analysis": self._run_wayback,
            "shodan_intel": self._run_shodan,
            "github_intel": self._run_github,
            "employee_intel": self._run_employee_intel,
            "attack_surface_mapping": self._run_attack_surface,
        }

        handler = handlers.get(task_type, self._run_full_osint)
        result = await handler(target, task.payload)

        # Store results on the bus for other agents
        await self.bus.set_state(f"osint:{target}", result)
        await self.bus.append_to_list(f"osint_findings:{target}", result.get("findings", []))

        return result

    async def _run_full_osint(self, target: str, payload: Dict) -> Dict[str, Any]:
        """Run full OSINT intelligence gathering."""
        if not self._osint_engine:
            return {"error": "OSINT engine not configured", "target": target}

        try:
            from hydra.osint import OSINTIntelligenceEngine
            report = await self._osint_engine.run_full_osint(target)
            return {
                "target": target,
                "assets_found": len(report.assets),
                "findings_count": len(report.findings),
                "duration": report.duration,
                "attack_surface": report.attack_surface,
                "findings": [
                    {
                        "type": f.finding_type,
                        "title": f.title,
                        "severity": f.severity,
                        "source": f.source,
                        "confidence": f.confidence,
                    }
                    for f in report.findings
                ],
                "assets": [
                    {
                        "asset": a.asset,
                        "type": a.asset_type,
                        "source": a.source,
                    }
                    for a in report.assets[:100]
                ],
            }
        except Exception as e:
            self.logger.error(f"Full OSINT failed: {e}")
            return {"error": str(e), "target": target}

    async def _run_cert_transparency(self, target: str, payload: Dict) -> Dict[str, Any]:
        """Run certificate transparency search."""
        if not self._osint_engine:
            return {"error": "OSINT engine not configured"}
        assets = await self._osint_engine.crtsh.search(target)
        return {
            "target": target,
            "subdomains": [a.asset for a in assets],
            "count": len(assets),
            "source": "crt.sh",
        }

    async def _run_dns_intel(self, target: str, payload: Dict) -> Dict[str, Any]:
        """Run DNS intelligence gathering."""
        if not self._osint_engine:
            return {"error": "OSINT engine not configured"}
        return await self._osint_engine.dns.gather_dns_intelligence(target)

    async def _run_wayback(self, target: str, payload: Dict) -> Dict[str, Any]:
        """Run Wayback Machine analysis."""
        if not self._osint_engine:
            return {"error": "OSINT engine not configured"}
        findings = await self._osint_engine.wayback.find_interesting_endpoints(target)
        return {
            "target": target,
            "findings": [
                {"type": f.finding_type, "title": f.title, "evidence": f.evidence}
                for f in findings
            ],
            "count": len(findings),
        }

    async def _run_shodan(self, target: str, payload: Dict) -> Dict[str, Any]:
        """Run Shodan intelligence."""
        if not self._osint_engine:
            return {"error": "OSINT engine not configured"}
        findings = await self._osint_engine.shodan.gather_intelligence(target)
        return {
            "target": target,
            "findings": [
                {"type": f.finding_type, "title": f.title, "severity": f.severity}
                for f in findings
            ],
        }

    async def _run_github(self, target: str, payload: Dict) -> Dict[str, Any]:
        """Run GitHub intelligence search."""
        if not self._github_intel:
            return {"error": "GitHub intelligence not configured"}
        findings = await self._github_intel.search_target(target)
        return {
            "target": target,
            "findings": [
                {
                    "type": f.finding_type,
                    "title": f.title,
                    "severity": f.severity,
                    "evidence": f.evidence,
                }
                for f in findings
            ],
            "leaked_secrets": sum(1 for f in findings if f.finding_type == "leaked_secret"),
        }

    async def _run_employee_intel(self, target: str, payload: Dict) -> Dict[str, Any]:
        """Run employee intelligence via GitHub."""
        if not self._github_intel:
            return {"error": "GitHub intelligence not configured"}
        org = payload.get("org", target.split(".")[0])
        findings = await self._github_intel.search_employee_repos(org, target)
        return {
            "target": target,
            "org": org,
            "findings": [
                {"type": f.finding_type, "title": f.title, "severity": f.severity}
                for f in findings
            ],
        }

    async def _run_attack_surface(self, target: str, payload: Dict) -> Dict[str, Any]:
        """Map the complete attack surface."""
        if not self._osint_engine:
            return {"error": "OSINT engine not configured"}
        report = await self._osint_engine.run_full_osint(target)
        return report.attack_surface
