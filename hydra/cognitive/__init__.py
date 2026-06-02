"""
╔══════════════════════════════════════════════════════════════╗
║  Cognitive Core — Autonomous Reasoning Loop                  ║
║  Observe → Understand → Reason → Simulate → Plan →           ║
║  Execute → Validate → Learn → Replan                         ║
║  The BRAIN of THENOTHING                                     ║
╚══════════════════════════════════════════════════════════════╝
"""

import asyncio
import json
import logging
import time
import uuid
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger("hydra.cognitive")


# ──────────────────────────────────────────────
#  Cognitive States
# ──────────────────────────────────────────────

class CognitivePhase(str, Enum):
    OBSERVE = "observe"           # Gather raw data about the target
    UNDERSTAND = "understand"     # Build internal model from observations
    REASON = "reason"             # Generate hypotheses + exploit theories
    SIMULATE = "simulate"         # Pre-execution attack simulation
    PLAN = "plan"                 # Generate executable plan
    EXECUTE = "execute"           # Run tools/payloads/agents
    VALIDATE = "validate"         # Evidence verification + debate
    LEARN = "learn"               # Update knowledge from outcomes
    REPLAN = "replan"             # Adapt strategy based on learnings


class BeliefConfidence(str, Enum):
    CERTAIN = "certain"           # Verified with evidence
    HIGH = "high"                 # Strong indicators, high probability
    MEDIUM = "medium"             # Reasonable indicators
    LOW = "low"                   # Weak signals, needs verification
    SPECULATIVE = "speculative"   # Hypothesis without evidence


class DecisionUrgency(str, Enum):
    CRITICAL = "critical"         # Requires immediate action
    HIGH = "high"                 # Should be next priority
    NORMAL = "normal"             # Standard queue
    LOW = "low"                   # Can defer
    BACKGROUND = "background"     # Process when idle


# ──────────────────────────────────────────────
#  Core Data Structures
# ──────────────────────────────────────────────

@dataclass
class Observation:
    """A raw observation about the target environment."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    source: str = ""              # agent, tool, osint, inference, browser
    observation_type: str = ""    # asset, technology, endpoint, vulnerability, behavior
    data: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.5
    timestamp: float = field(default_factory=time.time)
    raw_evidence: str = ""        # raw tool output / screenshot path / HTTP response


@dataclass
class Belief:
    """An inferred understanding about the target."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    belief_type: str = ""         # trust_boundary, tech_stack, auth_flow, vuln_hypothesis
    statement: str = ""           # Human-readable belief
    confidence: BeliefConfidence = BeliefConfidence.MEDIUM
    supporting_observations: List[str] = field(default_factory=list)
    contradicting_observations: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    invalidated: bool = False
    invalidation_reason: str = ""


@dataclass
class ExploitTheory:
    """A testable exploit theory with reasoning chain."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    title: str = ""
    description: str = ""
    attack_vector: str = ""       # xss, sqli, ssrf, idor, auth_bypass, etc.
    preconditions: List[str] = field(default_factory=list)
    attack_steps: List[str] = field(default_factory=list)
    expected_outcome: str = ""
    detection_probability: float = 0.5   # Estimated chance of being detected
    success_probability: float = 0.5     # Estimated chance of success
    blast_radius: str = ""               # Estimated impact scope
    required_skills: List[str] = field(default_factory=list)
    beliefs_required: List[str] = field(default_factory=list)
    confidence: float = 0.5
    status: str = "proposed"      # proposed, testing, confirmed, refuted, deferred
    evidence: List[str] = field(default_factory=list)
    reasoning_trace: List[str] = field(default_factory=list)


@dataclass
class CognitiveDecision:
    """A decision made by the cognitive loop."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    decision_type: str = ""       # investigate, exploit, expand_recon, defer, abort
    rationale: str = ""
    urgency: DecisionUrgency = DecisionUrgency.NORMAL
    actions: List[Dict[str, Any]] = field(default_factory=list)
    beliefs_considered: List[str] = field(default_factory=list)
    theories_considered: List[str] = field(default_factory=list)
    risk_assessment: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


@dataclass
class CognitiveState:
    """Full cognitive state snapshot."""
    cycle: int = 0
    phase: CognitivePhase = CognitivePhase.OBSERVE
    observations: List[Observation] = field(default_factory=list)
    beliefs: List[Belief] = field(default_factory=list)
    theories: List[ExploitTheory] = field(default_factory=list)
    decisions: List[CognitiveDecision] = field(default_factory=list)
    simulation_results: List[Dict[str, Any]] = field(default_factory=list)
    learnings: List[Dict[str, Any]] = field(default_factory=list)
    stealth_profile: Dict[str, Any] = field(default_factory=dict)
    target_understanding: float = 0.0   # 0-1 how well we understand the target
    started_at: float = field(default_factory=time.time)


# ──────────────────────────────────────────────
#  Cognitive Reasoning Loop
# ──────────────────────────────────────────────

class CognitiveLoop:
    """
    The autonomous cognitive reasoning loop.

    This is the BRAIN of THENOTHING — it continuously:
      1. OBSERVES the target environment
      2. UNDERSTANDS patterns and relationships
      3. REASONS about vulnerabilities and attack vectors
      4. SIMULATES attacks before execution
      5. PLANS optimal attack sequences
      6. EXECUTES with stealth awareness
      7. VALIDATES findings with evidence
      8. LEARNS from outcomes
      9. REPLANS based on learnings

    The loop runs continuously until:
      - Target understanding reaches threshold
      - All theories are tested
      - Budget/time limits reached
      - Manual stop signal

    Key principles:
      - Reason before execute
      - Simulate before interact
      - Minimize noise
      - Prioritize stealth and evidence
      - Continuously evolve methodology
    """

    MAX_CYCLES = 50
    UNDERSTANDING_THRESHOLD = 0.85
    MIN_THEORY_CONFIDENCE = 0.3

    def __init__(self, target: str):
        self.target = target
        self.state = CognitiveState()
        self._running = False
        self._cycle_callbacks: Dict[CognitivePhase, List[Callable]] = {}
        self._phase_handlers: Dict[CognitivePhase, Callable] = {}
        self._observation_index: Dict[str, Observation] = {}
        self._belief_index: Dict[str, Belief] = {}
        self._theory_index: Dict[str, ExploitTheory] = {}

        # Subsystem references (injected)
        self.world_model = None
        self.simulation_engine = None
        self.causal_engine = None
        self.stealth_engine = None
        self.skill_registry = None
        self.debate_engine = None
        self.planner = None
        self.executor = None
        self.learning_engine = None
        self.recon_expander = None

    # ── Subsystem Injection ───────────────────

    def attach(self, **subsystems):
        """Attach subsystem references."""
        for name, system in subsystems.items():
            if hasattr(self, name):
                setattr(self, name, system)
                logger.debug(f"Attached subsystem: {name}")

    # ── Main Loop ─────────────────────────────

    async def run(self, max_cycles: Optional[int] = None) -> CognitiveState:
        """
        Run the cognitive loop.

        Returns the final cognitive state after all cycles complete.
        """
        max_cycles = max_cycles or self.MAX_CYCLES
        self._running = True
        self.state.started_at = time.time()

        logger.info(f"🧠 Cognitive loop starting for target: {self.target}")

        try:
            while self._running and self.state.cycle < max_cycles:
                self.state.cycle += 1
                cycle_start = time.time()

                logger.info(
                    f"🔄 Cognitive Cycle {self.state.cycle}/{max_cycles} "
                    f"— Understanding: {self.state.target_understanding:.0%}"
                )

                # Execute each phase in sequence
                for phase in CognitivePhase:
                    if not self._running:
                        break
                    self.state.phase = phase
                    await self._execute_phase(phase)

                cycle_elapsed = time.time() - cycle_start
                logger.info(
                    f"✅ Cycle {self.state.cycle} complete in {cycle_elapsed:.1f}s — "
                    f"Observations: {len(self.state.observations)}, "
                    f"Beliefs: {len(self.state.beliefs)}, "
                    f"Theories: {len(self.state.theories)}"
                )

                # Check termination conditions
                if self._should_terminate():
                    logger.info("🏁 Cognitive loop termination condition met")
                    break

        except Exception as e:
            logger.error(f"Cognitive loop error: {e}", exc_info=True)
        finally:
            self._running = False
            elapsed = time.time() - self.state.started_at
            logger.info(
                f"🧠 Cognitive loop completed — {self.state.cycle} cycles, "
                f"{elapsed:.1f}s, {len(self.state.theories)} theories"
            )

        return self.state

    async def _execute_phase(self, phase: CognitivePhase):
        """Execute a single cognitive phase."""
        handler = self._phase_handlers.get(phase) or getattr(
            self, f"_phase_{phase.value}", None
        )
        if handler:
            try:
                await handler()
            except Exception as e:
                logger.warning(f"Phase {phase.value} error: {e}")

        # Fire callbacks
        for callback in self._cycle_callbacks.get(phase, []):
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(self.state)
                else:
                    callback(self.state)
            except Exception as e:
                logger.warning(f"Phase callback error: {e}")

    # ── Phase Implementations ─────────────────

    async def _phase_observe(self):
        """OBSERVE: Gather raw data about the target."""
        # This phase collects raw observations from all sources
        # In real execution, this invokes recon tools, OSINT, crawlers, etc.
        pass  # Populated by attached subsystems via register_phase_handler

    async def _phase_understand(self):
        """UNDERSTAND: Build internal model from observations."""
        # Correlate observations into beliefs
        new_beliefs = self._correlate_observations()
        for belief in new_beliefs:
            self.add_belief(belief)

        # Update target understanding score
        self._update_understanding_score()

    async def _phase_reason(self):
        """REASON: Generate exploit hypotheses from beliefs."""
        new_theories = self._generate_theories()
        for theory in new_theories:
            self.add_theory(theory)

        # Rank theories by expected value
        self._rank_theories()

    async def _phase_simulate(self):
        """SIMULATE: Pre-execution attack path simulation."""
        if self.simulation_engine:
            for theory in self._get_actionable_theories():
                sim_result = await self.simulation_engine.simulate(theory)
                self.state.simulation_results.append({
                    "theory_id": theory.id,
                    "feasibility": sim_result.get("feasibility", 0.5),
                    "detection_risk": sim_result.get("detection_risk", 0.5),
                    "expected_impact": sim_result.get("expected_impact", 0.3),
                    "recommended": sim_result.get("recommended", False),
                })

    async def _phase_plan(self):
        """PLAN: Generate executable plan from simulation results."""
        actionable = self._get_actionable_theories()
        if not actionable:
            return

        decisions = []
        for theory in actionable[:5]:  # Top 5 theories per cycle
            decision = CognitiveDecision(
                decision_type="investigate" if theory.success_probability < 0.7 else "exploit",
                rationale=f"Theory '{theory.title}' has {theory.success_probability:.0%} success probability",
                urgency=self._compute_urgency(theory),
                actions=[{
                    "type": theory.attack_vector,
                    "theory_id": theory.id,
                    "steps": theory.attack_steps,
                    "skills": theory.required_skills,
                }],
                theories_considered=[theory.id],
                risk_assessment={
                    "detection_probability": theory.detection_probability,
                    "blast_radius": theory.blast_radius,
                },
            )
            decisions.append(decision)
            self.state.decisions.append(decision)

    async def _phase_execute(self):
        """EXECUTE: Run tools/payloads with stealth awareness."""
        # Stealth-adjusted execution timing
        if self.stealth_engine:
            await self.stealth_engine.adjust_timing(self.state)

        # Execute decisions from plan phase
        # In production, this delegates to MCP tool server
        pass

    async def _phase_validate(self):
        """VALIDATE: Evidence verification + adversarial debate."""
        if self.debate_engine:
            for theory in self.state.theories:
                if theory.status == "testing" and theory.evidence:
                    # Run through debate system
                    pass  # Debate engine validates findings

    async def _phase_learn(self):
        """LEARN: Update knowledge from outcomes."""
        for theory in self.state.theories:
            if theory.status in ("confirmed", "refuted"):
                learning = {
                    "theory_id": theory.id,
                    "attack_vector": theory.attack_vector,
                    "outcome": theory.status,
                    "confidence": theory.confidence,
                    "timestamp": time.time(),
                }
                self.state.learnings.append(learning)

                if self.learning_engine:
                    await self.learning_engine.record(learning)

    async def _phase_replan(self):
        """REPLAN: Adapt strategy based on learnings."""
        # Check if new observations invalidate any beliefs
        self._invalidate_contradicted_beliefs()

        # Generate new theories from updated beliefs
        new_theories = self._generate_theories()
        for theory in new_theories:
            if theory.id not in self._theory_index:
                self.add_theory(theory)

        # Check if we need more recon
        if self.state.target_understanding < 0.5:
            if self.recon_expander:
                expansion = await self.recon_expander.suggest_expansion(
                    self.state.observations, self.state.beliefs
                )
                if expansion:
                    self.state.decisions.append(CognitiveDecision(
                        decision_type="expand_recon",
                        rationale="Target understanding below 50% — expanding reconnaissance",
                        urgency=DecisionUrgency.HIGH,
                        actions=expansion,
                    ))

    # ── Reasoning Helpers ─────────────────────

    def add_observation(self, obs: Observation):
        """Add an observation and trigger belief updates."""
        self.state.observations.append(obs)
        self._observation_index[obs.id] = obs

    def add_belief(self, belief: Belief):
        """Add or update a belief."""
        existing = self._belief_index.get(belief.id)
        if existing:
            existing.supporting_observations.extend(belief.supporting_observations)
            existing.updated_at = time.time()
            # Upgrade confidence if more evidence
            if len(existing.supporting_observations) > 3:
                existing.confidence = BeliefConfidence.HIGH
        else:
            self.state.beliefs.append(belief)
            self._belief_index[belief.id] = belief

    def add_theory(self, theory: ExploitTheory):
        """Add an exploit theory."""
        self.state.theories.append(theory)
        self._theory_index[theory.id] = theory

    def _correlate_observations(self) -> List[Belief]:
        """Correlate raw observations into beliefs about the target."""
        beliefs = []
        obs_by_type: Dict[str, List[Observation]] = {}
        for obs in self.state.observations:
            obs_by_type.setdefault(obs.observation_type, []).append(obs)

        # Technology correlation
        tech_obs = obs_by_type.get("technology", [])
        if tech_obs:
            techs = list({obs.data.get("name", "") for obs in tech_obs if obs.data.get("name")})
            if techs:
                beliefs.append(Belief(
                    id=f"belief_tech_stack",
                    belief_type="tech_stack",
                    statement=f"Target uses: {', '.join(techs)}",
                    confidence=BeliefConfidence.HIGH if len(tech_obs) > 2 else BeliefConfidence.MEDIUM,
                    supporting_observations=[o.id for o in tech_obs],
                ))

        # Auth flow inference
        endpoint_obs = obs_by_type.get("endpoint", [])
        auth_endpoints = [o for o in endpoint_obs if any(
            kw in o.data.get("path", "").lower()
            for kw in ["login", "auth", "oauth", "token", "session", "register"]
        )]
        if auth_endpoints:
            beliefs.append(Belief(
                id="belief_auth_system",
                belief_type="auth_flow",
                statement=f"Auth system detected with {len(auth_endpoints)} auth-related endpoints",
                confidence=BeliefConfidence.HIGH,
                supporting_observations=[o.id for o in auth_endpoints],
            ))

        # Trust boundary inference
        asset_obs = obs_by_type.get("asset", [])
        domains = list({o.data.get("domain", "") for o in asset_obs if o.data.get("domain")})
        if len(domains) > 1:
            beliefs.append(Belief(
                id="belief_multi_domain",
                belief_type="trust_boundary",
                statement=f"Multi-domain infrastructure: {', '.join(domains[:10])}",
                confidence=BeliefConfidence.MEDIUM,
                supporting_observations=[o.id for o in asset_obs[:20]],
            ))

        return beliefs

    def _generate_theories(self) -> List[ExploitTheory]:
        """Generate exploit theories from current beliefs."""
        theories = []
        existing_vectors = {t.attack_vector for t in self.state.theories}

        for belief in self.state.beliefs:
            if belief.invalidated:
                continue

            # Tech stack → vulnerability theories
            if belief.belief_type == "tech_stack":
                statement = belief.statement.lower()

                if "wordpress" in statement and "wordpress_xss" not in existing_vectors:
                    theories.append(ExploitTheory(
                        title="WordPress Plugin XSS",
                        attack_vector="wordpress_xss",
                        description="WordPress installations frequently have vulnerable plugins with XSS",
                        preconditions=["WordPress detected", "Plugins enumerated"],
                        attack_steps=[
                            "Enumerate installed plugins via wp-json/wp/v2/plugins",
                            "Check plugin versions against CVE database",
                            "Test discovered XSS vectors",
                        ],
                        success_probability=0.6,
                        detection_probability=0.2,
                        required_skills=["web_xss_reflected", "web_xss_stored"],
                        beliefs_required=[belief.id],
                        reasoning_trace=[f"Based on belief: {belief.statement}"],
                    ))

                if any(fw in statement for fw in ["react", "next.js", "vue", "angular"]):
                    if "frontend_secrets" not in existing_vectors:
                        theories.append(ExploitTheory(
                            title="Frontend JavaScript Secret Exposure",
                            attack_vector="frontend_secrets",
                            description="SPA frameworks often bundle secrets in client-side JavaScript",
                            preconditions=["SPA framework detected"],
                            attack_steps=[
                                "Analyze JavaScript bundles for API keys and secrets",
                                "Check for source maps exposing source code",
                                "Inspect __NEXT_DATA__ / window.__INITIAL_STATE__",
                            ],
                            success_probability=0.5,
                            detection_probability=0.05,
                            blast_radius="API key exposure → full API access",
                            required_skills=["frontend_source_maps", "frontend_localstorage"],
                            beliefs_required=[belief.id],
                        ))

            # Auth flow → auth bypass theories
            if belief.belief_type == "auth_flow" and "auth_bypass" not in existing_vectors:
                theories.append(ExploitTheory(
                    title="Authentication Bypass",
                    attack_vector="auth_bypass",
                    description="Test authentication system for bypass vulnerabilities",
                    preconditions=["Auth system identified"],
                    attack_steps=[
                        "Test JWT algorithm confusion (none, HS256 with RS256 key)",
                        "Test OAuth redirect_uri manipulation",
                        "Test session fixation/hijacking",
                        "Test password reset flow poisoning",
                    ],
                    success_probability=0.35,
                    detection_probability=0.15,
                    blast_radius="Account takeover → full user data",
                    required_skills=["auth_jwt_none", "auth_oauth_redirect", "auth_session_fixation"],
                    beliefs_required=[belief.id],
                ))

            # Trust boundary → SSRF/lateral movement theories
            if belief.belief_type == "trust_boundary" and "ssrf_internal" not in existing_vectors:
                theories.append(ExploitTheory(
                    title="SSRF to Internal Services",
                    attack_vector="ssrf_internal",
                    description="Multi-domain infrastructure may have SSRF paths to internal services",
                    preconditions=["Multiple domains detected", "URL-accepting parameters found"],
                    attack_steps=[
                        "Identify URL-accepting parameters",
                        "Test SSRF to internal IPs (127.0.0.1, 169.254.169.254)",
                        "Test SSRF to other internal domains",
                        "Attempt cloud metadata access",
                    ],
                    success_probability=0.3,
                    detection_probability=0.3,
                    blast_radius="Internal service access → cloud credentials",
                    required_skills=["web_ssrf", "cloud_aws_ssrf_metadata"],
                    beliefs_required=[belief.id],
                ))

        return theories

    def _rank_theories(self):
        """Rank theories by expected value (success × impact / detection risk)."""
        for theory in self.state.theories:
            if theory.status == "proposed":
                # Expected value = P(success) × impact / P(detection)
                impact_score = {"critical": 1.0, "high": 0.8, "medium": 0.5}.get(
                    theory.blast_radius, 0.3
                ) if isinstance(theory.blast_radius, str) else 0.5
                detection_risk = max(theory.detection_probability, 0.01)
                theory.confidence = (
                    theory.success_probability * impact_score / detection_risk
                )
                theory.confidence = min(theory.confidence, 1.0)

        self.state.theories.sort(key=lambda t: t.confidence, reverse=True)

    def _get_actionable_theories(self) -> List[ExploitTheory]:
        """Get theories ready for testing."""
        return [
            t for t in self.state.theories
            if t.status == "proposed"
            and t.confidence >= self.MIN_THEORY_CONFIDENCE
        ]

    def _compute_urgency(self, theory: ExploitTheory) -> DecisionUrgency:
        """Compute decision urgency from theory."""
        if theory.success_probability > 0.8:
            return DecisionUrgency.CRITICAL
        if theory.success_probability > 0.6:
            return DecisionUrgency.HIGH
        if theory.success_probability > 0.3:
            return DecisionUrgency.NORMAL
        return DecisionUrgency.LOW

    def _invalidate_contradicted_beliefs(self):
        """Check if any observations contradict existing beliefs."""
        for belief in self.state.beliefs:
            if belief.invalidated:
                continue
            if belief.contradicting_observations:
                if len(belief.contradicting_observations) >= len(belief.supporting_observations):
                    belief.invalidated = True
                    belief.invalidation_reason = "Contradicting evidence exceeds supporting evidence"
                    logger.info(f"Belief invalidated: {belief.statement}")

    def _update_understanding_score(self):
        """Update how well we understand the target."""
        factors = []

        # Factor 1: Observation coverage
        obs_types = {o.observation_type for o in self.state.observations}
        coverage = len(obs_types) / max(len(["asset", "technology", "endpoint",
                                              "vulnerability", "behavior", "infrastructure"]), 1)
        factors.append(min(coverage, 1.0))

        # Factor 2: Belief confidence
        if self.state.beliefs:
            avg_conf = sum(
                {"certain": 1.0, "high": 0.8, "medium": 0.5, "low": 0.3, "speculative": 0.1}
                .get(b.confidence.value, 0.5)
                for b in self.state.beliefs if not b.invalidated
            ) / len(self.state.beliefs)
            factors.append(avg_conf)
        else:
            factors.append(0.0)

        # Factor 3: Theory testing coverage
        if self.state.theories:
            tested = sum(1 for t in self.state.theories if t.status != "proposed")
            factors.append(min(tested / len(self.state.theories), 1.0))
        else:
            factors.append(0.0)

        self.state.target_understanding = sum(factors) / max(len(factors), 1)

    def _should_terminate(self) -> bool:
        """Check if the cognitive loop should terminate."""
        # Understanding threshold reached
        if self.state.target_understanding >= self.UNDERSTANDING_THRESHOLD:
            return True

        # All theories tested
        untested = [t for t in self.state.theories if t.status == "proposed"]
        if self.state.theories and not untested and self.state.cycle > 3:
            return True

        return False

    # ── External API ──────────────────────────

    def register_phase_handler(self, phase: CognitivePhase, handler: Callable):
        """Register a custom handler for a cognitive phase."""
        self._phase_handlers[phase] = handler

    def on_phase(self, phase: CognitivePhase, callback: Callable):
        """Register a callback for when a phase completes."""
        self._cycle_callbacks.setdefault(phase, []).append(callback)

    def stop(self):
        """Stop the cognitive loop."""
        self._running = False

    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of the cognitive state."""
        return {
            "target": self.target,
            "cycles": self.state.cycle,
            "phase": self.state.phase.value,
            "understanding": round(self.state.target_understanding, 3),
            "observations": len(self.state.observations),
            "beliefs": len([b for b in self.state.beliefs if not b.invalidated]),
            "theories": {
                "total": len(self.state.theories),
                "proposed": len([t for t in self.state.theories if t.status == "proposed"]),
                "confirmed": len([t for t in self.state.theories if t.status == "confirmed"]),
                "refuted": len([t for t in self.state.theories if t.status == "refuted"]),
            },
            "decisions": len(self.state.decisions),
            "learnings": len(self.state.learnings),
            "elapsed": round(time.time() - self.state.started_at, 1),
        }
