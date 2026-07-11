"""Offensive + Defensive Intelligence Service (Phase 10.8).

Dual-perspective analysis: every vulnerability is analyzed from both
the attacker's and defender's perspective. Generates offensive TTPs
alongside defensive countermeasures and detection signatures.
"""

import logging
import time
from typing import Any

from hydra.services.base import BaseService

logger = logging.getLogger("hydra.services.dual_intel")

OFFENSIVE_ASPECTS = (
    "exploitation_path", "payload_variants", "bypass_techniques",
    "chain_potential", "persistence_options", "lateral_movement",
)

DEFENSIVE_ASPECTS = (
    "detection_signatures", "mitigation_steps", "monitoring_rules",
    "hardening_measures", "incident_response", "forensic_artifacts",
)


class DualIntelService(BaseService):
    """Dual offensive + defensive intelligence for vulnerabilities."""

    def analyze(self, vuln_class: str, target: str = "",
                severity: str = "medium", context: dict | None = None) -> dict:
        """Generate dual offensive/defensive intelligence for a vulnerability."""
        ctx = context or {}

        offensive = self._generate_offensive(vuln_class, target, severity, ctx)
        defensive = self._generate_defensive(vuln_class, target, severity, ctx)
        risk = self._assess_risk(offensive, defensive, severity)

        self._emit("dual_intel.analyzed", {
            "vuln_class": vuln_class,
            "target": target,
            "severity": severity,
            "offensive_count": len(offensive),
            "defensive_count": len(defensive),
        })

        return {
            "status": "analyzed",
            "vuln_class": vuln_class,
            "target": target,
            "severity": severity,
            "offensive": offensive,
            "defensive": defensive,
            "risk_assessment": risk,
            "timestamp": time.time(),
        }

    def get_offensive_intel(self, vuln_class: str) -> dict:
        """Get offensive intelligence for a vulnerability class."""
        intel = self._vuln_offensive_map().get(vuln_class, {})
        return {
            "vuln_class": vuln_class,
            "exploitation": intel.get("exploitation", []),
            "payloads": intel.get("payloads", []),
            "bypasses": intel.get("bypasses", []),
            "chains": intel.get("chains", []),
        }

    def get_defensive_intel(self, vuln_class: str) -> dict:
        """Get defensive intelligence for a vulnerability class."""
        intel = self._vuln_defensive_map().get(vuln_class, {})
        return {
            "vuln_class": vuln_class,
            "detection": intel.get("detection", []),
            "mitigation": intel.get("mitigation", []),
            "monitoring": intel.get("monitoring", []),
            "hardening": intel.get("hardening", []),
        }

    def compare_perspectives(self, vuln_class: str) -> dict:
        """Side-by-side offensive vs defensive analysis."""
        offensive = self.get_offensive_intel(vuln_class)
        defensive = self.get_defensive_intel(vuln_class)

        gaps = []
        if offensive.get("bypasses") and not defensive.get("monitoring"):
            gaps.append("Bypass techniques exist but no monitoring rules defined")
        if offensive.get("chains") and not defensive.get("detection"):
            gaps.append("Chain potential exists but no detection signatures defined")

        return {
            "vuln_class": vuln_class,
            "offensive": offensive,
            "defensive": defensive,
            "coverage_gaps": gaps,
            "defensive_coverage": self._coverage_score(defensive),
        }

    def get_stats(self) -> dict[str, Any]:
        """Dual intelligence statistics."""
        off_map = self._vuln_offensive_map()
        def_map = self._vuln_defensive_map()
        return {
            "offensive_aspects": list(OFFENSIVE_ASPECTS),
            "defensive_aspects": list(DEFENSIVE_ASPECTS),
            "vuln_classes_with_offensive": len(off_map),
            "vuln_classes_with_defensive": len(def_map),
            "total_vuln_classes": len(set(list(off_map) + list(def_map))),
        }

    def _generate_offensive(self, vuln_class: str, target: str,
                            severity: str, ctx: dict) -> list[dict]:
        intel = self._vuln_offensive_map().get(vuln_class, {})
        results = []
        for path in intel.get("exploitation", ["Generic exploitation"]):
            results.append({
                "aspect": "exploitation_path",
                "detail": path,
                "severity": severity,
            })
        for payload in intel.get("payloads", []):
            results.append({
                "aspect": "payload_variants",
                "detail": payload,
            })
        for bypass in intel.get("bypasses", []):
            results.append({
                "aspect": "bypass_techniques",
                "detail": bypass,
            })
        for chain in intel.get("chains", []):
            results.append({
                "aspect": "chain_potential",
                "detail": chain,
            })
        if not results:
            results.append({
                "aspect": "exploitation_path",
                "detail": f"Standard {vuln_class} exploitation",
                "severity": severity,
            })
        return results

    def _generate_defensive(self, vuln_class: str, target: str,
                            severity: str, ctx: dict) -> list[dict]:
        intel = self._vuln_defensive_map().get(vuln_class, {})
        results = []
        for det in intel.get("detection", ["Monitor for anomalous patterns"]):
            results.append({
                "aspect": "detection_signatures",
                "detail": det,
            })
        for mit in intel.get("mitigation", []):
            results.append({
                "aspect": "mitigation_steps",
                "detail": mit,
            })
        for mon in intel.get("monitoring", []):
            results.append({
                "aspect": "monitoring_rules",
                "detail": mon,
            })
        for hard in intel.get("hardening", []):
            results.append({
                "aspect": "hardening_measures",
                "detail": hard,
            })
        if not results:
            results.append({
                "aspect": "detection_signatures",
                "detail": f"Standard {vuln_class} detection",
            })
        return results

    def _assess_risk(self, offensive: list[dict], defensive: list[dict],
                     severity: str) -> dict:
        sev_scores = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2, "info": 0.05}
        attack_surface = len(offensive) * sev_scores.get(severity, 0.5)
        defense_depth = len(defensive) * 0.3
        residual = max(0.0, min(1.0, attack_surface / max(attack_surface + defense_depth, 1)))
        return {
            "attack_surface_score": round(attack_surface, 2),
            "defense_depth_score": round(defense_depth, 2),
            "residual_risk": round(residual, 2),
            "risk_level": "high" if residual > 0.7 else "medium" if residual > 0.4 else "low",
        }

    def _coverage_score(self, defensive: dict) -> float:
        filled = sum(1 for v in defensive.values() if isinstance(v, list) and len(v) > 0)
        total = sum(1 for v in defensive.values() if isinstance(v, list))
        return round(filled / max(total, 1), 2)

    def _vuln_offensive_map(self) -> dict:
        return {
            "xss": {
                "exploitation": ["Reflected XSS via parameter injection", "Stored XSS via user input"],
                "payloads": ["<script>alert(document.domain)</script>", "<img onerror=alert(1) src=x>"],
                "bypasses": ["Unicode normalization", "Double encoding", "DOM clobbering"],
                "chains": ["XSS → Session hijack → Account takeover"],
            },
            "sqli": {
                "exploitation": ["Union-based extraction", "Boolean blind", "Time-based blind"],
                "payloads": ["' OR 1=1--", "' UNION SELECT NULL--"],
                "bypasses": ["WAF bypass via comments", "Case alternation"],
                "chains": ["SQLi → Data exfil → Credential theft"],
            },
            "ssrf": {
                "exploitation": ["Internal service access", "Cloud metadata access"],
                "payloads": ["http://169.254.169.254/latest/meta-data/"],
                "bypasses": ["DNS rebinding", "URL parser differential"],
                "chains": ["SSRF → IMDS → IAM credential theft → Account takeover"],
            },
            "idor": {
                "exploitation": ["Direct object reference manipulation"],
                "payloads": ["Sequential ID enumeration"],
                "bypasses": ["UUID guessing", "Parameter pollution"],
                "chains": ["IDOR → PII access → Account takeover"],
            },
            "ssti": {
                "exploitation": ["Template injection to RCE"],
                "payloads": ["{{7*7}}", "${7*7}"],
                "bypasses": ["Sandbox escape"],
                "chains": ["SSTI → RCE → Full compromise"],
            },
        }

    def _vuln_defensive_map(self) -> dict:
        return {
            "xss": {
                "detection": ["WAF rules for script tags", "CSP violation monitoring"],
                "mitigation": ["Output encoding", "Content Security Policy"],
                "monitoring": ["Alert on CSP violations", "Monitor DOM modifications"],
                "hardening": ["HttpOnly cookies", "Strict CSP", "X-XSS-Protection"],
            },
            "sqli": {
                "detection": ["SQL error pattern matching", "Query anomaly detection"],
                "mitigation": ["Parameterized queries", "Input validation"],
                "monitoring": ["Database query logging", "Error rate monitoring"],
                "hardening": ["Least privilege DB accounts", "WAF SQL rules"],
            },
            "ssrf": {
                "detection": ["Internal IP access monitoring", "DNS query logging"],
                "mitigation": ["URL allowlisting", "Block private IP ranges"],
                "monitoring": ["Outbound connection monitoring"],
                "hardening": ["Network segmentation", "IMDS v2"],
            },
            "idor": {
                "detection": ["Access pattern anomaly detection"],
                "mitigation": ["Authorization checks on every request"],
                "monitoring": ["Cross-user access logging"],
                "hardening": ["UUID instead of sequential IDs", "Object-level authorization"],
            },
            "ssti": {
                "detection": ["Template syntax in input monitoring"],
                "mitigation": ["Sandbox template execution", "Input sanitization"],
                "monitoring": ["Template error logging"],
                "hardening": ["Logic-less templates", "Restricted template context"],
            },
        }
