"""
╔══════════════════════════════════════════════════════════════╗
║  Causal Reasoning + Counterfactual Engine                    ║
║  "What if X?" · "What if Y instead of Z?" ·                 ║
║  "What defensive reaction is likely?" ·                      ║
║  "What attack path produces lower detection probability?"    ║
╚══════════════════════════════════════════════════════════════╝
"""

import logging
import time
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger("hydra.causal")


class CausalRelation(str, Enum):
    CAUSES = "causes"
    PREVENTS = "prevents"
    ENABLES = "enables"
    BLOCKS = "blocks"
    TRIGGERS = "triggers"
    MITIGATES = "mitigates"


@dataclass
class CausalLink:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:10])
    cause: str = ""
    effect: str = ""
    relation: CausalRelation = CausalRelation.CAUSES
    strength: float = 0.5
    conditions: List[str] = field(default_factory=list)


@dataclass
class Counterfactual:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:10])
    premise: str = ""
    probability_shift: float = 0.0
    detection_shift: float = 0.0
    reasoning: str = ""
    recommendation: str = ""


@dataclass
class DefenseReaction:
    trigger_action: str = ""
    predicted_reaction: str = ""
    reaction_probability: float = 0.5
    reaction_timing: str = ""
    countermeasure: str = ""
    escalation_risk: bool = False


# ── Causal Knowledge Base ─────────────────────

CAUSAL_CHAINS = {
    "xss_reflected": [
        CausalLink(cause="user_input_reflected", effect="xss_possible",
                   relation=CausalRelation.ENABLES, strength=0.7),
        CausalLink(cause="no_output_encoding", effect="xss_exploitable",
                   relation=CausalRelation.ENABLES, strength=0.9),
        CausalLink(cause="csp_strict", effect="xss_exploitable",
                   relation=CausalRelation.PREVENTS, strength=0.8),
        CausalLink(cause="waf_active", effect="xss_payload_blocked",
                   relation=CausalRelation.CAUSES, strength=0.6),
    ],
    "sqli": [
        CausalLink(cause="unsanitized_input", effect="sqli_possible",
                   relation=CausalRelation.ENABLES, strength=0.8),
        CausalLink(cause="parameterized_queries", effect="sqli_possible",
                   relation=CausalRelation.PREVENTS, strength=0.95),
        CausalLink(cause="error_messages_visible", effect="error_based_sqli",
                   relation=CausalRelation.ENABLES, strength=0.7),
    ],
    "ssrf": [
        CausalLink(cause="url_parameter_accepted", effect="ssrf_possible",
                   relation=CausalRelation.ENABLES, strength=0.6),
        CausalLink(cause="no_url_validation", effect="ssrf_exploitable",
                   relation=CausalRelation.ENABLES, strength=0.8),
        CausalLink(cause="cloud_metadata_accessible", effect="credential_theft",
                   relation=CausalRelation.CAUSES, strength=0.9),
    ],
    "auth_bypass": [
        CausalLink(cause="jwt_none_algorithm", effect="auth_bypass",
                   relation=CausalRelation.ENABLES, strength=0.95),
        CausalLink(cause="weak_session_management", effect="session_hijacking",
                   relation=CausalRelation.ENABLES, strength=0.7),
        CausalLink(cause="mfa_enabled", effect="auth_bypass",
                   relation=CausalRelation.PREVENTS, strength=0.7),
    ],
    "privilege_escalation": [
        CausalLink(cause="idor_present", effect="horizontal_escalation",
                   relation=CausalRelation.ENABLES, strength=0.8),
        CausalLink(cause="mass_assignment", effect="vertical_escalation",
                   relation=CausalRelation.ENABLES, strength=0.7),
        CausalLink(cause="rbac_enforced", effect="privilege_escalation",
                   relation=CausalRelation.PREVENTS, strength=0.85),
    ],
}

DEFENSE_REACTIONS = {
    "aggressive_scanning": DefenseReaction(
        trigger_action="High-rate scanning (>100 req/s)",
        predicted_reaction="IP blocking / rate limiting",
        reaction_probability=0.9, reaction_timing="immediate",
        countermeasure="Reduce rate to <10 req/s, distribute across IPs",
        escalation_risk=True,
    ),
    "sqli_payloads": DefenseReaction(
        trigger_action="SQL injection payloads in parameters",
        predicted_reaction="WAF blocks + alert to SOC",
        reaction_probability=0.8, reaction_timing="immediate",
        countermeasure="Use encoded/obfuscated payloads, time-based blind",
        escalation_risk=True,
    ),
    "xss_payloads": DefenseReaction(
        trigger_action="XSS payloads with <script> tags",
        predicted_reaction="WAF blocks, HTML encoding applied",
        reaction_probability=0.7, reaction_timing="immediate",
        countermeasure="Use event-handler based, DOM-based, or mutation XSS",
    ),
    "directory_bruteforce": DefenseReaction(
        trigger_action="Directory brute-forcing with wordlists",
        predicted_reaction="Rate limiting, 403 blocking",
        reaction_probability=0.6, reaction_timing="delayed",
        countermeasure="Use targeted wordlists, low rate, human-like intervals",
    ),
    "credential_stuffing": DefenseReaction(
        trigger_action="Multiple login attempts",
        predicted_reaction="Account lockout, CAPTCHA, IP ban",
        reaction_probability=0.85, reaction_timing="immediate",
        countermeasure="Distributed IPs, human-like timing",
        escalation_risk=True,
    ),
}


class CausalReasoningEngine:
    """
    Causal reasoning + counterfactual analysis engine.

    Reasons about:
      "What if X is true?"
      "What if we execute Y instead of Z?"
      "What defensive reaction is likely?"
      "What attack path produces lower detection probability?"
    """

    def __init__(self):
        self._causal_graph: Dict[str, List[CausalLink]] = dict(CAUSAL_CHAINS)
        self._counterfactuals: List[Counterfactual] = []
        self._custom_chains: List[CausalLink] = []

    def add_causal_link(self, link: CausalLink, chain: str = "custom"):
        self._causal_graph.setdefault(chain, []).append(link)
        self._custom_chains.append(link)

    def get_causal_chain(self, attack_vector: str) -> List[CausalLink]:
        return self._causal_graph.get(attack_vector, [])

    def get_enablers(self, effect: str) -> List[CausalLink]:
        enablers = []
        for chain in self._causal_graph.values():
            for link in chain:
                if link.effect == effect and link.relation in (
                    CausalRelation.ENABLES, CausalRelation.CAUSES):
                    enablers.append(link)
        return enablers

    def get_preventers(self, effect: str) -> List[CausalLink]:
        preventers = []
        for chain in self._causal_graph.values():
            for link in chain:
                if link.effect == effect and link.relation in (
                    CausalRelation.PREVENTS, CausalRelation.BLOCKS):
                    preventers.append(link)
        return preventers

    def analyze_preconditions(self, target_effect: str,
                              known_conditions: List[str]) -> Dict[str, Any]:
        enablers = self.get_enablers(target_effect)
        preventers = self.get_preventers(target_effect)
        known_set = set(c.lower() for c in known_conditions)

        met = [l for l in enablers if l.cause.lower() in known_set]
        unmet = [l for l in enablers if l.cause.lower() not in known_set]
        active_prev = [l for l in preventers if l.cause.lower() in known_set]

        en_score = sum(l.strength for l in met) / max(
            sum(l.strength for l in enablers), 0.01) if enablers else 0.5
        prev_penalty = sum(l.strength for l in active_prev)
        feasibility = max(0.0, min(1.0, en_score - prev_penalty))

        return {
            "target_effect": target_effect,
            "feasibility": round(feasibility, 3),
            "met_enablers": [{"cause": l.cause, "strength": l.strength} for l in met],
            "unmet_enablers": [{"cause": l.cause, "strength": l.strength} for l in unmet],
            "active_preventers": [{"cause": l.cause, "strength": l.strength} for l in active_prev],
            "recommendation": (
                "PROCEED" if feasibility > 0.6
                else "INVESTIGATE" if feasibility > 0.3
                else "DEFER"
            ),
        }

    def what_if(self, premise: str, attack_vector: str) -> Counterfactual:
        chain = self.get_causal_chain(attack_vector)
        relevant = [l for l in chain if premise.lower() in l.cause.lower()
                     or premise.lower() in l.effect.lower()]
        prob_shift = 0.0
        det_shift = 0.0
        for link in relevant:
            if link.relation == CausalRelation.ENABLES:
                prob_shift += link.strength * 0.3
            elif link.relation == CausalRelation.PREVENTS:
                prob_shift -= link.strength * 0.3
            elif link.relation == CausalRelation.CAUSES:
                prob_shift += link.strength * 0.2
                det_shift += 0.1
        cf = Counterfactual(
            premise=f"What if '{premise}' is true?",
            probability_shift=round(prob_shift, 3),
            detection_shift=round(det_shift, 3),
            reasoning=f"Analyzed {len(relevant)} causal links in {attack_vector}",
            recommendation="IMPROVES feasibility" if prob_shift > 0 else "REDUCES feasibility",
        )
        self._counterfactuals.append(cf)
        return cf

    def predict_defense_reaction(self, action: str) -> DefenseReaction:
        action_lower = action.lower()
        for key, reaction in DEFENSE_REACTIONS.items():
            if any(kw in action_lower for kw in key.split("_")):
                return reaction
        noise = 0.3
        if any(kw in action_lower for kw in ["scan", "brute", "fuzz"]):
            noise = 0.7
        if any(kw in action_lower for kw in ["passive", "analyze"]):
            noise = 0.1
        return DefenseReaction(
            trigger_action=action,
            predicted_reaction="Unknown pattern",
            reaction_probability=noise,
            reaction_timing="delayed" if noise < 0.5 else "immediate",
            countermeasure="Proceed with caution",
        )

    def predict_reactions_for_plan(self, steps: List[str]) -> List[DefenseReaction]:
        reactions = []
        cumulative = 0.0
        for step in steps:
            r = self.predict_defense_reaction(step)
            cumulative = 1 - (1 - cumulative) * (1 - r.reaction_probability * 0.3)
            r.trigger_action = f"[Step] {step} (cumulative: {cumulative:.0%})"
            reactions.append(r)
        return reactions

    def generate_hypotheses(self, known_conditions: List[str],
                            target_effects: Optional[List[str]] = None) -> List[Dict]:
        target_effects = target_effects or [
            "xss_exploitable", "sqli_possible", "ssrf_exploitable",
            "auth_bypass", "privilege_escalation", "credential_theft",
        ]
        hyps = []
        for effect in target_effects:
            analysis = self.analyze_preconditions(effect, known_conditions)
            if analysis["feasibility"] > 0.2:
                hyps.append({
                    "effect": effect,
                    "feasibility": analysis["feasibility"],
                    "met": [e["cause"] for e in analysis["met_enablers"]],
                    "missing": [e["cause"] for e in analysis["unmet_enablers"]],
                    "blockers": [e["cause"] for e in analysis["active_preventers"]],
                    "recommendation": analysis["recommendation"],
                })
        hyps.sort(key=lambda h: h["feasibility"], reverse=True)
        return hyps

    def predict_failure_modes(self, attack_vector: str,
                              known_defenses: List[str]) -> List[Dict]:
        chain = self.get_causal_chain(attack_vector)
        failures = []
        for link in chain:
            if link.relation in (CausalRelation.PREVENTS, CausalRelation.BLOCKS):
                if link.cause.lower() in [d.lower() for d in known_defenses]:
                    failures.append({
                        "failure_mode": f"{link.cause} blocks {link.effect}",
                        "probability": link.strength,
                        "severity": "high" if link.strength > 0.7 else "medium",
                    })
        failures.sort(key=lambda f: f["probability"], reverse=True)
        return failures

    def get_summary(self) -> Dict[str, Any]:
        return {
            "causal_chains": len(self._causal_graph),
            "total_links": sum(len(c) for c in self._causal_graph.values()),
            "counterfactuals_analyzed": len(self._counterfactuals),
            "defense_reactions_known": len(DEFENSE_REACTIONS),
        }
