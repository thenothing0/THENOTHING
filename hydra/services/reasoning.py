"""Causal Reasoning Engine (Phase 10.3).

Generates exploit hypotheses from observations using causal inference.
Counterfactual analysis: "What if X were different? Would Y still hold?"
Builds causal chains linking observations → beliefs → theories → testable hypotheses.
"""

import logging
import time
from typing import Any

from hydra.services.base import BaseService

logger = logging.getLogger("hydra.services.reasoning")

REASONING_MODES = (
    "deductive", "inductive", "abductive", "counterfactual", "analogical",
)

HYPOTHESIS_STATES = ("proposed", "testing", "confirmed", "refuted", "stale")


class Hypothesis:
    __slots__ = (
        "id", "title", "description", "mode", "state", "confidence",
        "evidence_for", "evidence_against", "created_at", "updated_at",
        "target", "vuln_class", "test_plan",
    )

    def __init__(self, title: str, description: str = "",
                 mode: str = "abductive", target: str = "",
                 vuln_class: str = ""):
        self.id = f"hyp-{int(time.time() * 1000)}"
        self.title = title
        self.description = description
        self.mode = mode
        self.state = "proposed"
        self.confidence = 0.5
        self.evidence_for: list[str] = []
        self.evidence_against: list[str] = []
        self.created_at = time.time()
        self.updated_at = time.time()
        self.target = target
        self.vuln_class = vuln_class
        self.test_plan: list[str] = []

    def to_dict(self) -> dict:
        return {
            "id": self.id, "title": self.title,
            "description": self.description, "mode": self.mode,
            "state": self.state, "confidence": self.confidence,
            "evidence_for": len(self.evidence_for),
            "evidence_against": len(self.evidence_against),
            "target": self.target, "vuln_class": self.vuln_class,
            "test_plan": self.test_plan,
            "created_at": self.created_at,
        }


class ReasoningService(BaseService):
    """Causal reasoning and hypothesis generation."""

    def __init__(self, event_bus, data_dir=None):
        super().__init__(event_bus, data_dir)
        self._hypotheses: dict[str, Hypothesis] = {}

    def generate_hypotheses(self, observations: list[dict],
                            target: str = "",
                            mode: str = "abductive") -> dict:
        """Generate exploit hypotheses from observations."""
        if mode not in REASONING_MODES:
            return {"status": "error", "error": f"Unknown mode: {mode}"}

        hypotheses = []

        for obs in observations:
            obs_type = obs.get("type", "")
            value = obs.get("value", "")

            if obs_type == "tech_stack":
                hyps = self._reason_from_tech(value, target, mode)
                hypotheses.extend(hyps)
            elif obs_type == "open_port":
                hyps = self._reason_from_port(value, target, mode)
                hypotheses.extend(hyps)
            elif obs_type == "header":
                hyps = self._reason_from_header(obs, target, mode)
                hypotheses.extend(hyps)
            elif obs_type == "error":
                hyps = self._reason_from_error(obs, target, mode)
                hypotheses.extend(hyps)
            else:
                h = Hypothesis(
                    f"Investigate {obs_type}: {value}",
                    mode=mode, target=target,
                )
                h.test_plan = [f"Probe {obs_type} for exploitation potential"]
                hypotheses.append(h)

        for h in hypotheses:
            self._hypotheses[h.id] = h

        self._emit("reasoning.hypotheses_generated", {
            "count": len(hypotheses),
            "target": target,
            "mode": mode,
        })

        return {
            "status": "generated",
            "hypotheses": [h.to_dict() for h in hypotheses],
            "count": len(hypotheses),
            "mode": mode,
            "target": target,
        }

    def counterfactual(self, hypothesis_id: str, variable: str,
                       new_value: str) -> dict:
        """Counterfactual: what if <variable> were <new_value>?"""
        hyp = self._hypotheses.get(hypothesis_id)
        if not hyp:
            return {"status": "error", "error": "Hypothesis not found"}

        analysis = {
            "original": hyp.to_dict(),
            "variable": variable,
            "new_value": new_value,
            "impact": self._assess_counterfactual(hyp, variable, new_value),
            "revised_confidence": max(0.1, hyp.confidence - 0.1),
        }

        self._emit("reasoning.counterfactual", {
            "hypothesis_id": hypothesis_id,
            "variable": variable,
        })

        return {"status": "analyzed", **analysis}

    def update_hypothesis(self, hypothesis_id: str,
                          evidence: str, supports: bool) -> dict:
        """Add evidence for or against a hypothesis."""
        hyp = self._hypotheses.get(hypothesis_id)
        if not hyp:
            return {"status": "error", "error": "Hypothesis not found"}

        if supports:
            hyp.evidence_for.append(evidence)
            hyp.confidence = min(1.0, hyp.confidence + 0.1)
        else:
            hyp.evidence_against.append(evidence)
            hyp.confidence = max(0.0, hyp.confidence - 0.15)

        if hyp.confidence >= 0.8 and len(hyp.evidence_for) >= 2:
            hyp.state = "confirmed"
        elif hyp.confidence <= 0.2:
            hyp.state = "refuted"
        else:
            hyp.state = "testing"

        hyp.updated_at = time.time()

        self._emit("reasoning.hypothesis_updated", {
            "hypothesis_id": hypothesis_id,
            "state": hyp.state,
            "confidence": hyp.confidence,
        })

        return {"status": "updated", **hyp.to_dict()}

    def list_hypotheses(self, state: str = "", target: str = "") -> list[dict]:
        """List hypotheses, optionally filtered."""
        results = []
        for h in self._hypotheses.values():
            if state and h.state != state:
                continue
            if target and h.target != target:
                continue
            results.append(h.to_dict())
        results.sort(key=lambda x: x["confidence"], reverse=True)
        return results

    def get_stats(self) -> dict[str, Any]:
        """Reasoning engine statistics."""
        by_state: dict[str, int] = {}
        by_mode: dict[str, int] = {}
        for h in self._hypotheses.values():
            by_state[h.state] = by_state.get(h.state, 0) + 1
            by_mode[h.mode] = by_mode.get(h.mode, 0) + 1
        return {
            "total_hypotheses": len(self._hypotheses),
            "by_state": by_state,
            "by_mode": by_mode,
            "reasoning_modes": list(REASONING_MODES),
            "hypothesis_states": list(HYPOTHESIS_STATES),
        }

    def _reason_from_tech(self, tech: str, target: str,
                          mode: str) -> list[Hypothesis]:
        tech_lower = tech.lower()
        hyps = []
        vuln_map = {
            "php": ("lfi", "Local file inclusion via PHP include"),
            "wordpress": ("sqli", "WordPress plugin SQL injection"),
            "apache": ("path_traversal", "Apache path traversal"),
            "nginx": ("misconfiguration", "Nginx alias traversal"),
            "node": ("ssrf", "SSRF via Node.js HTTP client"),
            "java": ("deserialization", "Java deserialization RCE"),
            "django": ("ssti", "Django template injection"),
            "flask": ("ssti", "Flask/Jinja2 SSTI"),
        }
        for key, (vuln, desc) in vuln_map.items():
            if key in tech_lower:
                h = Hypothesis(desc, mode=mode, target=target, vuln_class=vuln)
                h.test_plan = [f"Test {vuln} payloads against {target}"]
                h.evidence_for.append(f"Technology detected: {tech}")
                hyps.append(h)
        if not hyps:
            h = Hypothesis(
                f"Investigate {tech} for known CVEs",
                mode=mode, target=target,
            )
            h.test_plan = [f"Search CVE database for {tech}"]
            hyps.append(h)
        return hyps

    def _reason_from_port(self, port_info: str, target: str,
                          mode: str) -> list[Hypothesis]:
        h = Hypothesis(
            f"Service on {port_info} may expose attack surface",
            mode=mode, target=target,
        )
        h.test_plan = [f"Enumerate service on {port_info}"]
        return [h]

    def _reason_from_header(self, obs: dict, target: str,
                            mode: str) -> list[Hypothesis]:
        header = obs.get("name", "")
        value = obs.get("value", "")
        hyps = []
        if header.lower() == "server":
            h = Hypothesis(
                f"Server header leaks version: {value}",
                mode=mode, target=target, vuln_class="info_disclosure",
            )
            h.test_plan = ["Check for known CVEs for this version"]
            hyps.append(h)
        if "x-powered-by" in header.lower():
            h = Hypothesis(
                f"X-Powered-By reveals framework: {value}",
                mode=mode, target=target, vuln_class="info_disclosure",
            )
            hyps.append(h)
        if not hyps:
            h = Hypothesis(f"Analyze header {header}", mode=mode, target=target)
            hyps.append(h)
        return hyps

    def _reason_from_error(self, obs: dict, target: str,
                           mode: str) -> list[Hypothesis]:
        error_type = obs.get("value", "")
        h = Hypothesis(
            f"Error response may reveal internals: {error_type}",
            mode=mode, target=target, vuln_class="info_disclosure",
        )
        h.test_plan = ["Trigger verbose errors", "Check stack traces"]
        return [h]

    def _assess_counterfactual(self, hyp: Hypothesis, variable: str,
                               new_value: str) -> str:
        if variable == "waf":
            return "WAF removal would likely expose the vulnerability directly"
        if variable == "auth":
            return "Authentication change could alter exploitability"
        if variable == "version":
            return f"Version change to {new_value} may patch or introduce the vulnerability"
        return f"Changing {variable} to {new_value} requires re-evaluation"
