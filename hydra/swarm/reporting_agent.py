"""
╔══════════════════════════════════════════════════════════════╗
║  Reporting Agent — Structured Bug Bounty Report Generation  ║
╚══════════════════════════════════════════════════════════════╝
"""

import json
import logging
import time
from typing import Any, Dict
from pathlib import Path

from hydra.swarm.base_agent import BaseAgent
from hydra.memory.bus import MemoryBus, Task
from hydra.config import REPORTS_DIR

logger = logging.getLogger("hydra.agent.reporting")


class ReportingAgent(BaseAgent):
    AGENT_TYPE = "reporting"
    AGENT_NAME = "Reporting Agent"
    
    SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    
    def __init__(self, bus: MemoryBus, ai_router=None):
        super().__init__(bus)
        self.ai = ai_router
    
    async def execute(self, task: Task) -> Dict[str, Any]:
        if task.task_type == "report_generation":
            return await self._generate_report(task)
        raise ValueError(f"Unknown task type: {task.task_type}")
    
    async def _generate_report(self, task: Task) -> Dict[str, Any]:
        """Generate a structured bug bounty report."""
        target = task.payload["target"]
        scan_id = task.payload.get("scan_id", "unknown")
        context = task.payload.get("context", {})
        
        # Collect all findings
        findings = []
        attack_chains = []
        for phase_results in context.values():
            if isinstance(phase_results, list):
                for r in phase_results:
                    if isinstance(r, dict):
                        findings.extend(r.get("scored_findings",
                                        r.get("validated_findings",
                                        r.get("findings", []))))
                        attack_chains.extend(r.get("attack_chains",
                                            r.get("ranked_paths", [])))
        
        # Deduplicate findings
        seen = set()
        unique_findings = []
        for f in findings:
            key = f"{f.get('name','')}-{f.get('matched_at','')}"
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)
        
        # Sort by severity then confidence
        unique_findings.sort(key=lambda f: (
            self.SEVERITY_ORDER.get(f.get("severity", "info"), 5),
            -f.get("confidence_score", 0),
        ))
        
        # Build report
        report = {
            "meta": {
                "scan_id": scan_id,
                "target": target,
                "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "total_findings": len(unique_findings),
                "severity_breakdown": self._severity_breakdown(unique_findings),
            },
            "executive_summary": await self._executive_summary(
                target, unique_findings, attack_chains
            ),
            "findings": [
                self._format_finding(f, i + 1)
                for i, f in enumerate(unique_findings)
            ],
            "attack_chains": attack_chains[:10],
        }
        
        # Save reports
        report_dir = REPORTS_DIR / scan_id
        report_dir.mkdir(parents=True, exist_ok=True)
        
        # JSON report
        json_path = report_dir / "report.json"
        with open(json_path, "w", encoding="utf-8") as fp:
            json.dump(report, fp, indent=2, ensure_ascii=False)
        
        # Markdown report
        md_path = report_dir / "report.md"
        with open(md_path, "w", encoding="utf-8") as fp:
            fp.write(self._render_markdown(report))
        
        self.logger.info(f"Report saved: {report_dir}")
        return {
            "task_type": "report_generation",
            "target": target,
            "scan_id": scan_id,
            "report_path": str(report_dir),
            "total_findings": len(unique_findings),
            "severity_breakdown": report["meta"]["severity_breakdown"],
        }
    
    def _severity_breakdown(self, findings: list) -> Dict[str, int]:
        breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info").lower()
            breakdown[sev] = breakdown.get(sev, 0) + 1
        return breakdown
    
    def _format_finding(self, finding: Dict, index: int) -> Dict:
        return {
            "id": f"HYDRA-{index:04d}",
            "title": finding.get("name", "Unknown Finding"),
            "severity": finding.get("severity", "info"),
            "confidence": finding.get("confidence_score", 0),
            "type": finding.get("type", "unknown"),
            "host": finding.get("host", ""),
            "matched_at": finding.get("matched_at", ""),
            "description": finding.get("description", ""),
            "template_id": finding.get("template_id", ""),
        }
    
    async def _executive_summary(self, target, findings, chains) -> str:
        if self.ai:
            try:
                bd = self._severity_breakdown(findings)
                prompt = (
                    f"Write a concise executive summary for a bug bounty report.\n"
                    f"Target: {target}\n"
                    f"Findings: {bd}\n"
                    f"Attack chains: {len(chains)}\n"
                    "2-3 paragraphs, professional tone."
                )
                result = await self.ai.query(prompt, task_type="report_generation")
                if result:
                    return result
            except Exception:
                pass
        
        bd = self._severity_breakdown(findings)
        return (
            f"Security assessment of {target} identified {len(findings)} findings: "
            f"{bd['critical']} critical, {bd['high']} high, "
            f"{bd['medium']} medium, {bd['low']} low severity issues."
        )
    
    def _render_markdown(self, report: Dict) -> str:
        lines = [
            f"# HYDRA Security Report",
            f"## Target: {report['meta']['target']}",
            f"**Scan ID:** {report['meta']['scan_id']}  ",
            f"**Generated:** {report['meta']['generated_at']}  ",
            f"**Total Findings:** {report['meta']['total_findings']}",
            "",
            "## Executive Summary",
            report.get("executive_summary", ""),
            "",
            "## Severity Breakdown",
            "| Severity | Count |",
            "|----------|-------|",
        ]
        for sev, count in report["meta"]["severity_breakdown"].items():
            lines.append(f"| {sev.upper()} | {count} |")
        
        lines.extend(["", "## Findings", ""])
        for f in report.get("findings", []):
            lines.extend([
                f"### {f['id']} — {f['title']}",
                f"- **Severity:** {f['severity'].upper()}",
                f"- **Confidence:** {f['confidence']:.1%}",
                f"- **Host:** {f.get('host', 'N/A')}",
                f"- **Description:** {f.get('description', 'N/A')}",
                "",
            ])
        
        return "\n".join(lines)
