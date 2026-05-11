"""
╔══════════════════════════════════════════════════════════════╗
║  Environment Simulation Engine                               ║
║  Pre-execution attack path simulation, detection             ║
║  probability estimation, blast radius modeling,              ║
║  defensive system modeling, outcome forecasting              ║
╚══════════════════════════════════════════════════════════════╝
"""

import logging
import time
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger("hydra.simulation")


class DefenseType(str, Enum):
    WAF = "waf"
    IDS = "ids"
    IPS = "ips"
    RATE_LIMITER = "rate_limiter"
    CAPTCHA = "captcha"
    BOT_DETECTION = "bot_detection"
    CSP = "csp"
    CORS = "cors"
    MFA = "mfa"
    GEO_BLOCKING = "geo_blocking"
    IP_REPUTATION = "ip_reputation"
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"


class SimOutcome(str, Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    BLOCKED = "blocked"
    DETECTED = "detected"
    TIMEOUT = "timeout"
    UNKNOWN = "unknown"


@dataclass
class DefenseModel:
    """Model of a defensive system."""
    defense_type: DefenseType
    name: str = ""                    # cloudflare, akamai, mod_security, etc.
    confidence: float = 0.5           # How confident we are this defense exists
    blocking_patterns: List[str] = field(default_factory=list)
    bypass_strategies: List[str] = field(default_factory=list)
    detection_sensitivity: float = 0.5  # 0=permissive, 1=aggressive
    rate_limit: int = 0               # requests per second allowed
    known_weaknesses: List[str] = field(default_factory=list)


@dataclass
class AttackPath:
    """A simulated attack path."""
    id: str = ""
    steps: List[Dict[str, Any]] = field(default_factory=list)
    entry_point: str = ""
    target_asset: str = ""
    privilege_transitions: List[str] = field(default_factory=list)
    defenses_encountered: List[str] = field(default_factory=list)
    total_detection_probability: float = 0.0
    total_success_probability: float = 0.0
    estimated_duration: float = 0.0   # seconds
    blast_radius: List[str] = field(default_factory=list)
    risk_score: float = 0.0


@dataclass
class SimulationResult:
    """Result of an attack simulation."""
    theory_id: str = ""
    outcome: SimOutcome = SimOutcome.UNKNOWN
    feasibility: float = 0.0          # 0-1 overall feasibility
    detection_risk: float = 0.0       # 0-1 probability of detection
    expected_impact: float = 0.0      # 0-1 impact if successful
    recommended: bool = False
    attack_paths: List[AttackPath] = field(default_factory=list)
    defenses_modeled: List[DefenseModel] = field(default_factory=list)
    bypass_suggestions: List[str] = field(default_factory=list)
    risk_factors: Dict[str, float] = field(default_factory=dict)
    reasoning: str = ""
    simulation_time: float = 0.0


# ──────────────────────────────────────────────
#  Defense Behavior Models
# ──────────────────────────────────────────────

WAF_PROFILES = {
    "cloudflare": DefenseModel(
        defense_type=DefenseType.WAF,
        name="Cloudflare",
        confidence=0.9,
        blocking_patterns=[
            "<script", "onerror=", "onload=", "UNION SELECT",
            "../../", "etc/passwd", "cmd.exe", "eval(", "exec(",
        ],
        bypass_strategies=[
            "Chunked transfer encoding",
            "Unicode normalization bypass",
            "Request splitting",
            "Alternative content-types",
            "Polyglot payloads",
        ],
        detection_sensitivity=0.8,
        rate_limit=100,
        known_weaknesses=["Origin IP leak via DNS history", "Bypass via direct IP"],
    ),
    "akamai": DefenseModel(
        defense_type=DefenseType.WAF,
        name="Akamai Kona",
        confidence=0.85,
        blocking_patterns=[
            "<script", "document.cookie", "UNION", "SELECT",
            "' OR ", "cmd /c", "bash -i",
        ],
        bypass_strategies=[
            "Parameter pollution",
            "Double URL encoding",
            "Comment injection in SQL",
            "Null byte injection",
        ],
        detection_sensitivity=0.85,
        rate_limit=50,
    ),
    "mod_security": DefenseModel(
        defense_type=DefenseType.WAF,
        name="ModSecurity",
        confidence=0.7,
        blocking_patterns=[
            "select ", "union ", "<script>", "onerror", "../",
        ],
        bypass_strategies=[
            "Case variation",
            "Inline comments (/**/)",
            "Alternative whitespace characters",
            "Hex encoding",
        ],
        detection_sensitivity=0.6,
    ),
    "aws_waf": DefenseModel(
        defense_type=DefenseType.WAF,
        name="AWS WAF",
        confidence=0.8,
        blocking_patterns=[
            "<script", "UNION SELECT", "' OR ", "../../",
        ],
        bypass_strategies=[
            "Region-specific bypass",
            "Rate limit via distributed IPs",
            "Content-type manipulation",
        ],
        detection_sensitivity=0.7,
        rate_limit=200,
    ),
}

IDS_PROFILES = {
    "snort": DefenseModel(
        defense_type=DefenseType.IDS,
        name="Snort/Suricata",
        detection_sensitivity=0.7,
        blocking_patterns=["nmap", "sqlmap", "nikto", "dirbuster"],
        bypass_strategies=["Low-and-slow scanning", "Fragmented packets", "Encrypted channels"],
    ),
}


class EnvironmentSimulator:
    """
    Pre-execution attack simulation engine.

    Simulates attack paths BEFORE execution to:
      - Estimate exploit feasibility
      - Predict privilege transitions
      - Estimate detection probability
      - Model defensive systems (WAF, IDS, IPS)
      - Forecast likely outcomes
      - Estimate operational risk
      - Simulate blast radius

    The system MUST reason about:
      "What is likely to happen BEFORE execution."
    """

    def __init__(self):
        self._defense_models: Dict[str, DefenseModel] = {}
        self._simulation_history: List[SimulationResult] = []
        self._target_profiles: Dict[str, Dict[str, Any]] = {}

    # ── Defense Modeling ──────────────────────

    def model_defenses(self, target: str,
                       observations: List[Dict[str, Any]]) -> List[DefenseModel]:
        """Build defense models from observations."""
        models = []

        for obs in observations:
            # WAF detection from response headers
            headers = obs.get("headers", {})
            server = headers.get("server", "").lower()
            cf_ray = headers.get("cf-ray", "")
            x_akamai = headers.get("x-akamai-transformed", "")

            if cf_ray or "cloudflare" in server:
                models.append(WAF_PROFILES["cloudflare"])
            elif x_akamai or "akamai" in server:
                models.append(WAF_PROFILES["akamai"])
            elif "mod_security" in headers.get("server", "").lower():
                models.append(WAF_PROFILES["mod_security"])

            # Rate limiter detection
            if headers.get("x-ratelimit-limit") or headers.get("retry-after"):
                rl = DefenseModel(
                    defense_type=DefenseType.RATE_LIMITER,
                    name="Rate Limiter",
                    confidence=0.9,
                    rate_limit=int(headers.get("x-ratelimit-limit", "100")),
                )
                models.append(rl)

            # CSP detection
            if headers.get("content-security-policy"):
                csp = DefenseModel(
                    defense_type=DefenseType.CSP,
                    name="Content Security Policy",
                    confidence=0.95,
                    blocking_patterns=["inline scripts", "eval"],
                    bypass_strategies=["CSP bypass via allowed domains", "JSONP gadgets"],
                )
                models.append(csp)

            # Bot detection
            status = obs.get("status_code", 200)
            if status == 403 or obs.get("captcha_detected"):
                models.append(DefenseModel(
                    defense_type=DefenseType.BOT_DETECTION,
                    name="Bot Detection",
                    confidence=0.7,
                    bypass_strategies=["Browser emulation", "Header rotation", "Human-like timing"],
                ))

        # Deduplicate by type
        seen_types = set()
        unique = []
        for m in models:
            key = f"{m.defense_type.value}:{m.name}"
            if key not in seen_types:
                seen_types.add(key)
                unique.append(m)
                self._defense_models[key] = m

        return unique

    # ── Attack Simulation ─────────────────────

    async def simulate(self, theory, target_profile: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Simulate an exploit theory before execution.

        Returns feasibility, detection risk, expected impact.
        """
        start = time.time()

        # Build attack path
        attack_path = self._build_attack_path(theory)

        # Calculate detection probability
        detection_risk = self._estimate_detection(theory, attack_path)

        # Calculate feasibility
        feasibility = self._estimate_feasibility(theory, attack_path)

        # Calculate expected impact
        impact = self._estimate_impact(theory)

        # Generate bypass suggestions if defenses present
        bypass_suggestions = self._generate_bypass_suggestions(attack_path)

        # Decision: recommend or not
        risk_reward = feasibility * impact / max(detection_risk, 0.01)
        recommended = risk_reward > 0.5 and detection_risk < 0.7

        result = SimulationResult(
            theory_id=getattr(theory, 'id', ''),
            outcome=SimOutcome.SUCCESS if recommended else SimOutcome.BLOCKED,
            feasibility=round(feasibility, 3),
            detection_risk=round(detection_risk, 3),
            expected_impact=round(impact, 3),
            recommended=recommended,
            attack_paths=[attack_path],
            defenses_modeled=list(self._defense_models.values()),
            bypass_suggestions=bypass_suggestions,
            risk_factors={
                "detection_risk": detection_risk,
                "feasibility": feasibility,
                "impact": impact,
                "risk_reward_ratio": round(risk_reward, 3),
            },
            reasoning=self._generate_reasoning(theory, feasibility, detection_risk, impact),
            simulation_time=round(time.time() - start, 3),
        )

        self._simulation_history.append(result)

        return {
            "feasibility": result.feasibility,
            "detection_risk": result.detection_risk,
            "expected_impact": result.expected_impact,
            "recommended": result.recommended,
            "bypass_suggestions": result.bypass_suggestions,
            "reasoning": result.reasoning,
        }

    def _build_attack_path(self, theory) -> AttackPath:
        """Build an attack path from a theory."""
        steps = []
        detection_prob = 0.0
        success_prob = 1.0

        attack_steps = getattr(theory, 'attack_steps', [])
        for i, step in enumerate(attack_steps):
            step_detection = self._step_detection_probability(step)
            step_success = self._step_success_probability(step)

            steps.append({
                "step": i + 1,
                "action": step,
                "detection_probability": step_detection,
                "success_probability": step_success,
            })

            # Cumulative probability
            detection_prob = 1 - (1 - detection_prob) * (1 - step_detection)
            success_prob *= step_success

        return AttackPath(
            id=getattr(theory, 'id', ''),
            steps=steps,
            entry_point=getattr(theory, 'attack_vector', ''),
            defenses_encountered=[m.name for m in self._defense_models.values()],
            total_detection_probability=round(detection_prob, 3),
            total_success_probability=round(success_prob, 3),
            estimated_duration=len(steps) * 5.0,  # rough estimate
            risk_score=round(detection_prob * (1 - success_prob), 3),
        )

    def _step_detection_probability(self, step: str) -> float:
        """Estimate detection probability for a single step."""
        step_lower = step.lower()
        base = 0.1

        # High-noise actions
        if any(kw in step_lower for kw in ["brute", "fuzz", "scan", "enumerate"]):
            base += 0.3
        if any(kw in step_lower for kw in ["exploit", "inject", "payload"]):
            base += 0.2
        if any(kw in step_lower for kw in ["nmap", "sqlmap", "nikto"]):
            base += 0.4

        # Low-noise actions
        if any(kw in step_lower for kw in ["passive", "analyze", "inspect", "check"]):
            base -= 0.05

        # Defense amplification
        for defense in self._defense_models.values():
            if defense.defense_type == DefenseType.IDS:
                base *= 1 + defense.detection_sensitivity
            if defense.defense_type == DefenseType.WAF:
                for pattern in defense.blocking_patterns:
                    if pattern.lower() in step_lower:
                        base += 0.2

        return min(max(base, 0.01), 0.99)

    def _step_success_probability(self, step: str) -> float:
        """Estimate success probability for a single step."""
        step_lower = step.lower()
        base = 0.7

        # Higher success for passive steps
        if any(kw in step_lower for kw in ["passive", "analyze", "check", "inspect"]):
            base = 0.9
        # Lower success for active exploitation
        if any(kw in step_lower for kw in ["exploit", "bypass", "escalat"]):
            base = 0.4
        if any(kw in step_lower for kw in ["brute", "crack"]):
            base = 0.3

        return min(max(base, 0.05), 0.99)

    def _estimate_detection(self, theory, attack_path: AttackPath) -> float:
        """Estimate overall detection risk."""
        base = attack_path.total_detection_probability

        # Adjust based on theory's detection_probability
        theory_det = getattr(theory, 'detection_probability', 0.5)
        return (base * 0.6 + theory_det * 0.4)

    def _estimate_feasibility(self, theory, attack_path: AttackPath) -> float:
        """Estimate overall attack feasibility."""
        base = attack_path.total_success_probability

        # Adjust for preconditions
        preconditions = getattr(theory, 'preconditions', [])
        if preconditions:
            # Assume some preconditions may not be met
            precondition_factor = 0.8 ** len(preconditions)
            base *= precondition_factor

        # Adjust for WAF presence
        waf_count = sum(1 for d in self._defense_models.values()
                        if d.defense_type == DefenseType.WAF)
        if waf_count > 0:
            base *= 0.7 ** waf_count

        return min(max(base, 0.01), 0.99)

    def _estimate_impact(self, theory) -> float:
        """Estimate impact if exploit succeeds."""
        blast = getattr(theory, 'blast_radius', '')
        if not blast:
            return 0.3

        blast_lower = blast.lower() if isinstance(blast, str) else str(blast).lower()
        if any(kw in blast_lower for kw in ["full", "all users", "admin", "rce", "database"]):
            return 0.95
        if any(kw in blast_lower for kw in ["account", "credential", "token", "api"]):
            return 0.7
        if any(kw in blast_lower for kw in ["session", "xss", "redirect"]):
            return 0.5
        return 0.3

    def _generate_bypass_suggestions(self, attack_path: AttackPath) -> List[str]:
        """Generate bypass suggestions for encountered defenses."""
        suggestions = []
        for defense in self._defense_models.values():
            for strategy in defense.bypass_strategies:
                if strategy not in suggestions:
                    suggestions.append(f"[{defense.name}] {strategy}")
        return suggestions[:10]

    def _generate_reasoning(self, theory, feasibility: float,
                            detection: float, impact: float) -> str:
        """Generate human-readable simulation reasoning."""
        title = getattr(theory, 'title', 'Unknown')
        parts = [f"Simulation of '{title}':"]

        if feasibility > 0.7:
            parts.append(f"HIGH feasibility ({feasibility:.0%}) — attack path is viable")
        elif feasibility > 0.4:
            parts.append(f"MEDIUM feasibility ({feasibility:.0%}) — some obstacles expected")
        else:
            parts.append(f"LOW feasibility ({feasibility:.0%}) — significant barriers")

        if detection > 0.5:
            parts.append(f"WARNING: High detection risk ({detection:.0%})")
        elif detection > 0.2:
            parts.append(f"Moderate detection risk ({detection:.0%})")
        else:
            parts.append(f"Low detection risk ({detection:.0%}) — stealth viable")

        if self._defense_models:
            defenses = [d.name for d in self._defense_models.values()]
            parts.append(f"Defenses modeled: {', '.join(defenses)}")

        risk_reward = feasibility * impact / max(detection, 0.01)
        if risk_reward > 1.0:
            parts.append(f"RECOMMENDED — risk/reward ratio: {risk_reward:.2f}")
        else:
            parts.append(f"CAUTION — risk/reward ratio: {risk_reward:.2f}")

        return ". ".join(parts)

    # ── Privilege Escalation Simulation ────────

    def simulate_privilege_escalation(self,
                                      current_role: str,
                                      target_role: str,
                                      known_paths: List[Dict]) -> Dict[str, Any]:
        """Simulate privilege escalation paths."""
        paths = []
        for path in known_paths:
            steps = path.get("steps", [])
            total_success = 1.0
            for step in steps:
                total_success *= step.get("success_probability", 0.5)
            paths.append({
                "path": path,
                "total_success_probability": round(total_success, 3),
                "steps_count": len(steps),
            })

        paths.sort(key=lambda p: p["total_success_probability"], reverse=True)

        return {
            "current_role": current_role,
            "target_role": target_role,
            "viable_paths": len([p for p in paths if p["total_success_probability"] > 0.1]),
            "best_path": paths[0] if paths else None,
            "paths": paths[:5],
        }

    # ── Summary ───────────────────────────────

    def get_summary(self) -> Dict[str, Any]:
        """Get simulation statistics."""
        if not self._simulation_history:
            return {"total_simulations": 0}
        recommended = sum(1 for s in self._simulation_history if s.recommended)
        avg_feasibility = sum(s.feasibility for s in self._simulation_history) / len(self._simulation_history)
        avg_detection = sum(s.detection_risk for s in self._simulation_history) / len(self._simulation_history)
        return {
            "total_simulations": len(self._simulation_history),
            "recommended": recommended,
            "blocked": len(self._simulation_history) - recommended,
            "avg_feasibility": round(avg_feasibility, 3),
            "avg_detection_risk": round(avg_detection, 3),
            "defenses_modeled": len(self._defense_models),
        }
