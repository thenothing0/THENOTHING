"""
╔══════════════════════════════════════════════════════════════╗
║  Researcher Profile Engine — Dynamic Persona Switching       ║
║  Adapts attack methodology, tool selection, stealth level,   ║
║  and reasoning strategy based on target context              ║
║  NO COMPETITOR HAS THIS CAPABILITY                           ║
╚══════════════════════════════════════════════════════════════╝
"""

import logging
import time
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field

logger = logging.getLogger("hydra.researcher_profiles")


class ProfileType(str, Enum):
    STEALTH = "stealth_researcher"
    AGGRESSIVE = "aggressive_hunter"
    RECON = "recon_specialist"
    CLOUD = "cloud_hunter"
    API = "api_specialist"
    BUSINESS_LOGIC = "business_logic_researcher"
    EXPLOIT_CHAIN = "exploit_chain_analyst"
    MOBILE = "mobile_researcher"
    WEB3 = "web3_auditor"
    BALANCED = "balanced"


@dataclass
class SkillWeight:
    """Skill weighting within a profile."""
    skill_id: str
    weight: float = 1.0          # 0-2 multiplier
    priority: int = 5            # 1=highest, 10=lowest


@dataclass
class ResearcherProfile:
    """A complete researcher persona configuration."""
    profile_type: ProfileType
    name: str
    description: str

    # Stealth configuration
    stealth_mode: str = "normal"  # aggressive, normal, cautious, stealth, ghost
    max_requests_per_second: float = 10.0

    # Tool preferences
    preferred_tools: List[str] = field(default_factory=list)
    avoided_tools: List[str] = field(default_factory=list)

    # Skill weights
    skill_weights: List[SkillWeight] = field(default_factory=list)

    # Attack methodology
    attack_priorities: List[str] = field(default_factory=list)

    # Cognitive parameters
    min_theory_confidence: float = 0.3
    max_theories_per_cycle: int = 5
    max_cycles: int = 10
    simulation_required: bool = True
    debate_required: bool = True

    # Scan parameters
    crawl_depth: int = 3
    max_concurrent_tools: int = 3
    timeout_per_tool: int = 120

    # Trigger conditions (when to auto-activate)
    trigger_tech: List[str] = field(default_factory=list)
    trigger_industry: List[str] = field(default_factory=list)
    trigger_conditions: List[str] = field(default_factory=list)

    # Performance tracking
    times_activated: int = 0
    total_findings: int = 0
    success_rate: float = 0.0


# ──────────────────────────────────────────────
#  Built-in Profiles
# ──────────────────────────────────────────────

BUILTIN_PROFILES: Dict[ProfileType, ResearcherProfile] = {
    ProfileType.STEALTH: ResearcherProfile(
        profile_type=ProfileType.STEALTH,
        name="Ghost Researcher",
        description="Minimal footprint, passive-first, maximum OPSEC. "
                    "Avoids noisy tools, uses stealth mode, prioritizes "
                    "passive recon and inference over active scanning.",
        stealth_mode="ghost",
        max_requests_per_second=0.5,
        preferred_tools=["subfinder", "gau", "waybackurls", "httpx"],
        avoided_tools=["nmap", "dirsearch", "ffuf", "sqlmap"],
        attack_priorities=[
            "information_disclosure", "misconfigurations",
            "exposed_secrets", "default_credentials",
            "subdomain_takeover", "cors_misconfiguration",
        ],
        min_theory_confidence=0.5,
        max_theories_per_cycle=3,
        max_cycles=15,
        simulation_required=True,
        crawl_depth=2,
        max_concurrent_tools=1,
        trigger_conditions=["waf_detected", "ids_detected", "rate_limited"],
    ),

    ProfileType.AGGRESSIVE: ResearcherProfile(
        profile_type=ProfileType.AGGRESSIVE,
        name="Full-Spectrum Hunter",
        description="Maximum coverage, all tools active, speed-focused. "
                    "Tests every attack vector with high parallelism.",
        stealth_mode="aggressive",
        max_requests_per_second=50.0,
        preferred_tools=[
            "subfinder", "httpx", "nuclei", "katana", "ffuf",
            "dirsearch", "nmap", "sqlmap", "dalfox",
        ],
        attack_priorities=[
            "sqli", "xss", "ssrf", "rce", "auth_bypass",
            "idor", "ssti", "lfi", "rfi", "xxe",
        ],
        min_theory_confidence=0.2,
        max_theories_per_cycle=10,
        max_cycles=20,
        simulation_required=False,
        debate_required=True,
        crawl_depth=5,
        max_concurrent_tools=10,
        timeout_per_tool=300,
    ),

    ProfileType.RECON: ResearcherProfile(
        profile_type=ProfileType.RECON,
        name="Recon Specialist",
        description="Deep asset discovery, infrastructure mapping, "
                    "naming pattern prediction, trust boundary analysis.",
        stealth_mode="cautious",
        max_requests_per_second=5.0,
        preferred_tools=[
            "subfinder", "amass", "httpx", "katana", "waybackurls",
            "gau", "gospider", "dnsx", "hakrawler",
        ],
        attack_priorities=[
            "subdomain_enumeration", "port_scanning",
            "tech_fingerprinting", "infrastructure_mapping",
            "cloud_asset_discovery", "api_discovery",
        ],
        min_theory_confidence=0.4,
        max_cycles=8,
        crawl_depth=4,
        max_concurrent_tools=5,
    ),

    ProfileType.CLOUD: ResearcherProfile(
        profile_type=ProfileType.CLOUD,
        name="Cloud Hunter",
        description="AWS/GCP/Azure focus. Cloud misconfigurations, "
                    "S3 buckets, IAM issues, metadata exploitation.",
        stealth_mode="cautious",
        max_requests_per_second=3.0,
        preferred_tools=["subfinder", "httpx", "nuclei"],
        attack_priorities=[
            "s3_bucket_misconfiguration", "cloud_metadata_ssrf",
            "iam_privilege_escalation", "azure_blob_exposure",
            "gcp_bucket_misconfiguration", "kubernetes_exposure",
            "docker_api_exposure", "terraform_state_exposure",
        ],
        trigger_tech=["aws", "gcp", "azure", "kubernetes", "docker", "terraform"],
        trigger_industry=["saas", "cloud", "infrastructure"],
        crawl_depth=3,
        skill_weights=[
            SkillWeight("cloud_aws_ssrf_metadata", 2.0, 1),
            SkillWeight("cloud_s3_bucket", 2.0, 1),
            SkillWeight("cloud_azure_blob", 1.8, 2),
        ],
    ),

    ProfileType.API: ResearcherProfile(
        profile_type=ProfileType.API,
        name="API Specialist",
        description="REST/GraphQL/gRPC focus. Auth flows, IDOR, "
                    "mass assignment, rate limiting, broken auth.",
        stealth_mode="normal",
        max_requests_per_second=5.0,
        preferred_tools=["httpx", "nuclei", "ffuf", "katana"],
        attack_priorities=[
            "idor", "broken_auth", "mass_assignment",
            "graphql_introspection", "jwt_manipulation",
            "oauth_redirect", "api_rate_limit_bypass",
            "bola", "bfla", "excessive_data_exposure",
        ],
        trigger_tech=["graphql", "rest", "grpc", "swagger", "openapi"],
        crawl_depth=2,
        skill_weights=[
            SkillWeight("api_idor", 2.0, 1),
            SkillWeight("api_graphql", 2.0, 1),
            SkillWeight("auth_jwt_none", 1.8, 2),
            SkillWeight("auth_oauth_redirect", 1.8, 2),
        ],
    ),

    ProfileType.BUSINESS_LOGIC: ResearcherProfile(
        profile_type=ProfileType.BUSINESS_LOGIC,
        name="Business Logic Researcher",
        description="Manual-like testing focus. Logic flaws, race "
                    "conditions, payment bypass, workflow abuse.",
        stealth_mode="stealth",
        max_requests_per_second=2.0,
        preferred_tools=["httpx", "katana"],
        avoided_tools=["nuclei", "ffuf", "sqlmap"],
        attack_priorities=[
            "business_logic_flaw", "race_condition",
            "payment_bypass", "privilege_escalation",
            "workflow_abuse", "coupon_reuse",
            "negative_quantity", "time_of_check_time_of_use",
        ],
        min_theory_confidence=0.4,
        max_theories_per_cycle=3,
        simulation_required=True,
        debate_required=True,
        crawl_depth=2,
        max_concurrent_tools=1,
    ),

    ProfileType.EXPLOIT_CHAIN: ResearcherProfile(
        profile_type=ProfileType.EXPLOIT_CHAIN,
        name="Exploit Chain Analyst",
        description="Chain-building specialist. Combines low-severity "
                    "findings into high-impact attack chains.",
        stealth_mode="cautious",
        max_requests_per_second=3.0,
        attack_priorities=[
            "privilege_escalation_chain", "ssrf_to_rce",
            "xss_to_account_takeover", "info_leak_to_auth_bypass",
            "open_redirect_to_oauth_theft", "cors_to_data_exfil",
        ],
        min_theory_confidence=0.3,
        max_theories_per_cycle=8,
        max_cycles=15,
    ),

    ProfileType.MOBILE: ResearcherProfile(
        profile_type=ProfileType.MOBILE,
        name="Mobile Researcher",
        description="Mobile API testing, certificate pinning bypass, "
                    "deep link abuse, local storage analysis.",
        stealth_mode="normal",
        attack_priorities=[
            "mobile_api_auth", "certificate_pinning_bypass",
            "deep_link_hijack", "insecure_local_storage",
            "webview_xss", "intent_injection",
        ],
        trigger_tech=["ios", "android", "react-native", "flutter"],
    ),

    ProfileType.WEB3: ResearcherProfile(
        profile_type=ProfileType.WEB3,
        name="Web3 Auditor",
        description="Smart contract analysis, DeFi protocol testing, "
                    "bridge vulnerabilities, oracle manipulation.",
        stealth_mode="normal",
        attack_priorities=[
            "reentrancy", "flash_loan_attack", "oracle_manipulation",
            "front_running", "access_control", "integer_overflow",
        ],
        trigger_tech=["solidity", "ethereum", "web3", "defi", "nft"],
    ),

    ProfileType.BALANCED: ResearcherProfile(
        profile_type=ProfileType.BALANCED,
        name="Balanced Researcher",
        description="Default profile. Balanced approach across all "
                    "attack vectors with moderate stealth.",
        stealth_mode="normal",
        max_requests_per_second=10.0,
        attack_priorities=[
            "xss", "sqli", "ssrf", "idor", "auth_bypass",
            "misconfigurations", "information_disclosure",
        ],
        crawl_depth=3,
        max_concurrent_tools=5,
    ),
}


# ──────────────────────────────────────────────
#  Profile Engine
# ──────────────────────────────────────────────

class ResearcherProfileEngine:
    """
    Dynamic researcher persona engine.

    Automatically selects and switches between specialized
    researcher profiles based on:
      - Target technology stack
      - Defensive posture (WAF/IDS detection)
      - Industry/sector
      - Exploit probability per vector
      - Historical success rates

    Profiles control:
      - Stealth mode and timing
      - Tool selection and priorities
      - Skill weights and attack methodology
      - Cognitive loop parameters
      - Scan depth and concurrency
    """

    def __init__(self):
        self._profiles = dict(BUILTIN_PROFILES)
        self._active_profile: Optional[ResearcherProfile] = None
        self._profile_history: List[Dict[str, Any]] = []
        self._custom_profiles: Dict[str, ResearcherProfile] = {}

    @property
    def active(self) -> ResearcherProfile:
        """Get the currently active profile."""
        if self._active_profile is None:
            self._active_profile = self._profiles[ProfileType.BALANCED]
        return self._active_profile

    def select_profile(self,
                       tech_stack: List[str] = None,
                       industry: str = "",
                       defensive_signals: List[str] = None,
                       force: Optional[ProfileType] = None,
                       ) -> ResearcherProfile:
        """
        Auto-select the best researcher profile for the target.

        Selection logic:
          1. If forced, use that profile
          2. If defensive signals (WAF/IDS), switch to stealth
          3. Match tech stack to profile triggers
          4. Match industry to profile triggers
          5. Fall back to balanced
        """
        tech_stack = tech_stack or []
        defensive_signals = defensive_signals or []
        tech_lower = [t.lower() for t in tech_stack]

        if force:
            return self.activate(force)

        # Rule 1: Defensive signals → stealth
        if any(s in defensive_signals for s in
               ["waf_detected", "ids_detected", "rate_limited",
                "captcha", "ip_ban"]):
            logger.info("🕵️ Defensive signals detected → Stealth profile")
            return self.activate(ProfileType.STEALTH)

        # Rule 2: Tech stack matching
        best_match = ProfileType.BALANCED
        best_score = 0

        for ptype, profile in self._profiles.items():
            if ptype == ProfileType.BALANCED:
                continue
            score = 0
            for trigger in profile.trigger_tech:
                if trigger.lower() in tech_lower:
                    score += 1
            if industry and industry.lower() in [
                i.lower() for i in profile.trigger_industry
            ]:
                score += 0.5
            # Weight by historical success
            if profile.success_rate > 0:
                score *= (1 + profile.success_rate)
            if score > best_score:
                best_score = score
                best_match = ptype

        if best_score > 0:
            return self.activate(best_match)

        # Rule 3: Industry matching
        for ptype, profile in self._profiles.items():
            if industry and industry.lower() in [
                i.lower() for i in profile.trigger_industry
            ]:
                return self.activate(ptype)

        return self.activate(ProfileType.BALANCED)

    def activate(self, profile_type: ProfileType) -> ResearcherProfile:
        """Activate a specific profile."""
        profile = self._profiles.get(profile_type)
        if not profile:
            logger.warning(f"Profile {profile_type} not found, using balanced")
            profile = self._profiles[ProfileType.BALANCED]

        old_name = self._active_profile.name if self._active_profile else "none"
        self._active_profile = profile
        profile.times_activated += 1

        self._profile_history.append({
            "from": old_name,
            "to": profile.name,
            "profile_type": profile.profile_type.value,
            "timestamp": time.time(),
        })

        logger.info(
            f"🎭 Profile activated: {profile.name} "
            f"(stealth={profile.stealth_mode}, "
            f"rps={profile.max_requests_per_second}, "
            f"priorities={profile.attack_priorities[:3]})"
        )

        return profile

    def get_cognitive_params(self) -> Dict[str, Any]:
        """Get cognitive loop parameters from active profile."""
        p = self.active
        return {
            "min_theory_confidence": p.min_theory_confidence,
            "max_theories_per_cycle": p.max_theories_per_cycle,
            "max_cycles": p.max_cycles,
            "simulation_required": p.simulation_required,
            "debate_required": p.debate_required,
        }

    def get_stealth_config(self) -> Dict[str, Any]:
        """Get stealth configuration from active profile."""
        p = self.active
        return {
            "mode": p.stealth_mode,
            "max_rps": p.max_requests_per_second,
            "max_concurrent": p.max_concurrent_tools,
            "crawl_depth": p.crawl_depth,
        }

    def get_tool_preferences(self) -> Dict[str, Any]:
        """Get tool preferences from active profile."""
        p = self.active
        return {
            "preferred": p.preferred_tools,
            "avoided": p.avoided_tools,
            "timeout": p.timeout_per_tool,
        }

    def record_outcome(self, findings_count: int, success: bool = True):
        """Record hunt outcome for profile performance tracking."""
        p = self.active
        p.total_findings += findings_count
        total = p.times_activated
        if total > 0:
            p.success_rate = (
                p.success_rate * (total - 1) + (1.0 if success else 0.0)
            ) / total

    def register_custom_profile(self, profile: ResearcherProfile):
        """Register a custom researcher profile."""
        self._profiles[profile.profile_type] = profile
        self._custom_profiles[profile.profile_type.value] = profile

    def get_summary(self) -> Dict[str, Any]:
        return {
            "active_profile": self.active.name if self._active_profile else "none",
            "profile_type": self.active.profile_type.value,
            "total_profiles": len(self._profiles),
            "switches": len(self._profile_history),
            "profile_stats": {
                p.name: {
                    "activated": p.times_activated,
                    "findings": p.total_findings,
                    "success_rate": round(p.success_rate, 3),
                }
                for p in self._profiles.values()
                if p.times_activated > 0
            },
        }
