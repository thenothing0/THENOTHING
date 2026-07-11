"""TTP Engine Service — MITRE ATT&CK technique extraction and playbook generation.

Bridges the adversary_intel module to expose TTP analysis as a service:
extraction from text, technique-capability mapping, coverage analysis,
and playbook generation from confirmed findings.
"""

import logging
import re
from typing import Any

from hydra.services.base import BaseService

logger = logging.getLogger("hydra.services.ttp")


class TTPService(BaseService):
    """MITRE ATT&CK TTP extraction, mapping, and playbook generation."""

    def _mapping(self):
        from hydra.adversary_intel.attack_mapping import AttackMapping
        return AttackMapping()

    def _coverage(self):
        from hydra.adversary_intel.technique_coverage import TechniqueCoverageAnalyzer
        return TechniqueCoverageAnalyzer()

    def extract_ttps(self, text: str) -> dict[str, Any]:
        """Extract MITRE ATT&CK TTPs from free text."""
        tactics = list(set(re.findall(r"TA\d{4}", text)))
        techniques = list(set(re.findall(r"T\d{4}(?:\.\d{3})?", text)))
        tactic_keywords = {
            "reconnaissance": "TA0043",
            "initial access": "TA0001",
            "execution": "TA0002",
            "persistence": "TA0003",
            "privilege escalation": "TA0004",
            "defense evasion": "TA0005",
            "credential access": "TA0006",
            "discovery": "TA0007",
            "lateral movement": "TA0008",
            "collection": "TA0009",
            "exfiltration": "TA0010",
            "command and control": "TA0011",
            "impact": "TA0040",
            "resource development": "TA0042",
        }
        lower = text.lower()
        for keyword, tactic_id in tactic_keywords.items():
            if keyword in lower and tactic_id not in tactics:
                tactics.append(tactic_id)
        technique_keywords = {
            "sql injection": "T1190",
            "xss": "T1059.007",
            "cross-site scripting": "T1059.007",
            "ssrf": "T1090",
            "server-side request forgery": "T1090",
            "phishing": "T1566",
            "brute force": "T1110",
            "credential stuffing": "T1110.004",
            "directory traversal": "T1083",
            "path traversal": "T1083",
            "command injection": "T1059",
            "remote code execution": "T1203",
            "rce": "T1203",
            "idor": "T1078",
            "deserialization": "T1059",
        }
        for keyword, tech_id in technique_keywords.items():
            if keyword in lower and tech_id not in techniques:
                techniques.append(tech_id)

        result = {
            "tactics": sorted(tactics),
            "techniques": sorted(techniques),
            "tactic_count": len(tactics),
            "technique_count": len(techniques),
        }
        self._emit("ttp.extracted", {
            "tactic_count": len(tactics),
            "technique_count": len(techniques),
        })
        return result

    def get_technique_info(self, technique_id: str) -> dict[str, Any]:
        """Get info about a specific ATT&CK technique."""
        try:
            mapping = self._mapping()
            caps = mapping.capabilities_for(technique_id)
            return {
                "technique_id": technique_id,
                "capabilities": caps,
                "capability_count": len(caps),
            }
        except Exception as e:
            logger.error("get_technique_info(%s) failed: %s", technique_id, e)
            return {"technique_id": technique_id, "capabilities": [],
                    "capability_count": 0, "error": str(e)}

    def capabilities_for_technique(self, technique_id: str) -> list[str]:
        """Map a technique to supporting capabilities."""
        try:
            return self._mapping().capabilities_for(technique_id)
        except Exception:
            return []

    def techniques_for_capability(self, capability_id: str) -> list[str]:
        """Map a capability to its ATT&CK techniques."""
        try:
            return self._mapping().techniques_for_capability(capability_id)
        except Exception:
            return []

    def get_coverage(self, *, limit: int = 50) -> list[dict]:
        """Get technique coverage analysis."""
        try:
            analyzer = self._coverage()
            ranked = analyzer.rank(limit=limit)
            return [
                {
                    "technique_id": tc.technique_id,
                    "status": tc.status.value if hasattr(tc.status, "value") else str(tc.status),
                    "capabilities": tc.capabilities,
                    "effectiveness": getattr(tc, "effectiveness", 0),
                    "fragile": getattr(tc, "fragile", False),
                }
                for tc in ranked
            ]
        except Exception as e:
            logger.error("get_coverage failed: %s", e)
            return []

    def get_coverage_summary(self) -> dict[str, Any]:
        """Summarize technique coverage by status."""
        try:
            analyzer = self._coverage()
            by_status = analyzer.by_status()
            return {
                k.value if hasattr(k, "value") else str(k): v
                for k, v in by_status.items()
            }
        except Exception:
            return {}

    def generate_playbook(self, findings: list[dict]) -> dict[str, Any]:
        """Generate an attack playbook from a set of findings.

        Maps each finding's vuln_class to ATT&CK techniques and produces
        an ordered sequence of TTP steps with chaining opportunities.
        """
        vuln_technique_map = {
            "xss": ["T1059.007"],
            "sqli": ["T1190"],
            "ssrf": ["T1090"],
            "rce": ["T1203"],
            "idor": ["T1078"],
            "ssti": ["T1059"],
            "lfi": ["T1083"],
            "path_traversal": ["T1083"],
            "open_redirect": ["T1566"],
            "csrf": ["T1185"],
            "xxe": ["T1059"],
            "cmdi": ["T1059"],
            "auth_bypass": ["T1078"],
            "info_disclosure": ["T1082"],
        }

        steps = []
        all_techniques = set()

        for i, f in enumerate(findings):
            vc = f.get("vuln_class", "unknown")
            techs = vuln_technique_map.get(vc, [])
            all_techniques.update(techs)
            step = {
                "order": i + 1,
                "finding": f.get("title", vc),
                "vuln_class": vc,
                "severity": f.get("severity", "unknown"),
                "techniques": techs,
                "action": f"Exploit {vc} at {f.get('endpoint', 'target')}",
            }
            steps.append(step)

        chains = []
        if len(steps) >= 2:
            for i in range(len(steps) - 1):
                chains.append({
                    "from": steps[i]["finding"],
                    "to": steps[i + 1]["finding"],
                    "leverage": f"{steps[i]['vuln_class']} → {steps[i+1]['vuln_class']}",
                })

        return {
            "steps": steps,
            "step_count": len(steps),
            "techniques": sorted(all_techniques),
            "technique_count": len(all_techniques),
            "chains": chains,
            "chain_count": len(chains),
        }

    def get_stats(self) -> dict[str, Any]:
        """TTP engine statistics."""
        try:
            coverage = self.get_coverage_summary()
            return {
                "coverage_summary": coverage,
                "total_techniques": sum(coverage.values()) if coverage else 0,
            }
        except Exception:
            return {"coverage_summary": {}, "total_techniques": 0}
