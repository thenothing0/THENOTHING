"""
╔══════════════════════════════════════════════════════════════╗
║  Universal Skills Engine — Autonomous Vulnerability Skills  ║
║  Dynamic skill generation, composition, evolution, and      ║
║  learning with semantic memory + attack graph integration   ║
╚══════════════════════════════════════════════════════════════╝
"""

import json
import logging
import time
import uuid
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger("hydra.skills")


class SkillCategory(str, Enum):
    WEB = "web"
    API = "api"
    AUTH = "auth"
    CLOUD = "cloud"
    KUBERNETES = "kubernetes"
    GRAPHQL = "graphql"
    BUSINESS_LOGIC = "business_logic"
    AI_SECURITY = "ai_security"
    FRONTEND = "frontend"
    MOBILE = "mobile"
    CICD = "cicd"
    OSINT = "osint"
    EXPLOIT_CHAINS = "exploit_chains"
    VALIDATION = "validation"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ExploitHypothesis:
    """A testable exploit hypothesis within a skill."""
    id: str
    title: str
    description: str
    preconditions: List[str] = field(default_factory=list)
    test_steps: List[str] = field(default_factory=list)
    payloads: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    severity: Severity = Severity.MEDIUM
    confidence: float = 0.5
    cwe: str = ""
    owasp: str = ""
    chain_next: List[str] = field(default_factory=list)  # IDs of chained hypotheses


@dataclass
class ReconStep:
    """A reconnaissance step within a skill."""
    name: str
    tool: str = ""                  # MCP tool to execute
    command_template: str = ""
    parse_logic: str = ""           # what to extract from output
    condition: str = ""             # when to execute
    priority: int = 2


@dataclass
class ValidationRule:
    """Evidence validation rule."""
    name: str
    check_type: str                 # response_code, body_contains, header_match, timing, diff
    expected: Any = None
    confidence_boost: float = 0.2
    false_positive_indicators: List[str] = field(default_factory=list)


@dataclass
class Skill:
    """
    Universal Vulnerability Skill.

    Contains everything needed for autonomous vulnerability detection:
    reasoning heuristics, exploit hypotheses, recon methods, validation,
    attack chains, payload strategies, and evidence requirements.
    """
    id: str
    name: str
    category: SkillCategory
    description: str
    version: str = "1.0"
    severity: Severity = Severity.MEDIUM
    tags: List[str] = field(default_factory=list)

    # Core reasoning
    reasoning_heuristics: List[str] = field(default_factory=list)
    fingerprints: List[Dict[str, str]] = field(default_factory=list)
    exploit_hypotheses: List[ExploitHypothesis] = field(default_factory=list)

    # Recon + execution
    recon_steps: List[ReconStep] = field(default_factory=list)
    payloads: List[str] = field(default_factory=list)
    payload_mutations: List[str] = field(default_factory=list)

    # Validation + evidence
    validation_rules: List[ValidationRule] = field(default_factory=list)
    evidence_requirements: List[str] = field(default_factory=list)
    false_positive_patterns: List[str] = field(default_factory=list)

    # Chain + expansion
    chain_from: List[str] = field(default_factory=list)   # skill IDs that lead here
    chain_to: List[str] = field(default_factory=list)      # skill IDs this leads to
    framework_associations: List[str] = field(default_factory=list)

    # Reporting
    report_template: str = ""
    remediation: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

    # Learning metrics
    success_count: int = 0
    failure_count: int = 0
    false_positive_count: int = 0
    last_success: float = 0.0
    confidence_score: float = 0.5

    @property
    def success_rate(self) -> float:
        total = self.success_count + self.failure_count
        return self.success_count / total if total > 0 else 0.0

    def record_success(self):
        self.success_count += 1
        self.last_success = time.time()
        self.confidence_score = min(1.0, self.confidence_score + 0.05)

    def record_failure(self):
        self.failure_count += 1
        self.confidence_score = max(0.1, self.confidence_score - 0.02)

    def record_false_positive(self):
        self.false_positive_count += 1
        self.confidence_score = max(0.1, self.confidence_score - 0.05)


class SkillRegistry:
    """
    Central registry for all vulnerability skills.

    Supports:
      - Dynamic skill registration and hot-loading
      - Category-based lookup
      - Tag-based search
      - Framework-aware activation
      - Success-rate ranking
      - Skill composition (chaining)
      - Evolution tracking
    """

    def __init__(self):
        self._skills: Dict[str, Skill] = {}
        self._by_category: Dict[str, List[str]] = {}
        self._by_tag: Dict[str, List[str]] = {}

    def register(self, skill: Skill):
        """Register a skill."""
        self._skills[skill.id] = skill
        cat = skill.category.value
        self._by_category.setdefault(cat, []).append(skill.id)
        for tag in skill.tags:
            self._by_tag.setdefault(tag, []).append(skill.id)

    def get(self, skill_id: str) -> Optional[Skill]:
        return self._skills.get(skill_id)

    def get_by_category(self, category: str) -> List[Skill]:
        ids = self._by_category.get(category, [])
        return [self._skills[sid] for sid in ids if sid in self._skills]

    def get_by_tag(self, tag: str) -> List[Skill]:
        ids = self._by_tag.get(tag, [])
        return [self._skills[sid] for sid in ids if sid in self._skills]

    def search(self, query: str) -> List[Skill]:
        """Search skills by name, tag, or description."""
        q = query.lower()
        return [s for s in self._skills.values()
                if q in s.name.lower() or q in s.description.lower()
                or any(q in t for t in s.tags)]

    def get_for_technologies(self, techs: List[str]) -> List[Skill]:
        """Get skills relevant to detected technologies."""
        results = []
        tech_lower = {t.lower() for t in techs}
        for skill in self._skills.values():
            assoc = {a.lower() for a in skill.framework_associations}
            if assoc & tech_lower:
                results.append(skill)
        return sorted(results, key=lambda s: s.confidence_score, reverse=True)

    def get_chain(self, start_skill_id: str, max_depth: int = 5) -> List[List[Skill]]:
        """Get exploit chains starting from a skill."""
        chains = []
        def walk(current_id: str, path: List[str], depth: int):
            if depth >= max_depth:
                return
            skill = self._skills.get(current_id)
            if not skill:
                return
            for next_id in skill.chain_to:
                if next_id not in path and next_id in self._skills:
                    new_path = path + [next_id]
                    chains.append([self._skills[sid] for sid in new_path])
                    walk(next_id, new_path, depth + 1)
        walk(start_skill_id, [start_skill_id], 0)
        return chains

    def rank_by_success(self, category: Optional[str] = None) -> List[Skill]:
        """Rank skills by success rate."""
        skills = self.get_by_category(category) if category else list(self._skills.values())
        return sorted(skills, key=lambda s: (s.success_rate, s.confidence_score), reverse=True)

    @property
    def total_skills(self) -> int:
        return len(self._skills)

    @property
    def categories(self) -> List[str]:
        return list(self._by_category.keys())

    def get_summary(self) -> Dict[str, Any]:
        return {
            "total_skills": self.total_skills,
            "categories": {cat: len(ids) for cat, ids in self._by_category.items()},
            "total_hypotheses": sum(len(s.exploit_hypotheses) for s in self._skills.values()),
            "total_payloads": sum(len(s.payloads) for s in self._skills.values()),
        }


class SkillComposer:
    """
    Composes hybrid skills from existing skills.

    Capabilities:
      - Merge recon steps from multiple skills
      - Combine exploit hypotheses
      - Build multi-stage attack workflows
      - Create framework-specific skill variants
    """

    def __init__(self, registry: SkillRegistry):
        self._registry = registry

    def compose(self, skill_ids: List[str], name: str,
                category: SkillCategory = SkillCategory.EXPLOIT_CHAINS) -> Skill:
        """Compose a new skill from multiple existing skills."""
        composed = Skill(
            id=f"composed_{str(uuid.uuid4())[:8]}",
            name=name,
            category=category,
            description=f"Composed from: {', '.join(skill_ids)}",
            tags=["composed", "chain"],
        )

        for sid in skill_ids:
            skill = self._registry.get(sid)
            if not skill:
                continue
            composed.exploit_hypotheses.extend(skill.exploit_hypotheses)
            composed.recon_steps.extend(skill.recon_steps)
            composed.payloads.extend(skill.payloads)
            composed.validation_rules.extend(skill.validation_rules)
            composed.tags.extend(skill.tags)
            composed.remediation.extend(skill.remediation)

        # Deduplicate
        composed.tags = list(set(composed.tags))
        return composed

    def create_variant(self, skill_id: str, framework: str,
                       extra_payloads: Optional[List[str]] = None) -> Optional[Skill]:
        """Create a framework-specific variant of a skill."""
        base = self._registry.get(skill_id)
        if not base:
            return None

        variant = Skill(
            id=f"{base.id}_{framework.lower()}",
            name=f"{base.name} ({framework})",
            category=base.category,
            description=f"{base.description} — {framework}-specific variant",
            severity=base.severity,
            tags=base.tags + [framework.lower()],
            reasoning_heuristics=base.reasoning_heuristics.copy(),
            exploit_hypotheses=base.exploit_hypotheses.copy(),
            recon_steps=base.recon_steps.copy(),
            payloads=base.payloads + (extra_payloads or []),
            validation_rules=base.validation_rules.copy(),
            evidence_requirements=base.evidence_requirements.copy(),
            framework_associations=[framework],
            remediation=base.remediation.copy(),
        )
        return variant


class SkillEvolver:
    """
    Evolves skills based on learning feedback.

    Tracks success/failure rates, adjusts confidence,
    promotes effective payloads, and demotes false positives.
    """

    def __init__(self, registry: SkillRegistry):
        self._registry = registry
        self._evolution_log: List[Dict[str, Any]] = []

    def record_outcome(self, skill_id: str, success: bool,
                       false_positive: bool = False, context: Optional[Dict] = None):
        """Record the outcome of a skill execution."""
        skill = self._registry.get(skill_id)
        if not skill:
            return

        if false_positive:
            skill.record_false_positive()
        elif success:
            skill.record_success()
        else:
            skill.record_failure()

        self._evolution_log.append({
            "skill_id": skill_id, "success": success,
            "false_positive": false_positive,
            "timestamp": time.time(),
            "context": context or {},
        })

    def get_evolution_stats(self, skill_id: str) -> Dict[str, Any]:
        skill = self._registry.get(skill_id)
        if not skill:
            return {}
        return {
            "success_rate": skill.success_rate,
            "confidence": skill.confidence_score,
            "total_runs": skill.success_count + skill.failure_count,
            "false_positives": skill.false_positive_count,
        }

    def suggest_improvements(self, skill_id: str) -> List[str]:
        """Suggest improvements for a skill based on history."""
        skill = self._registry.get(skill_id)
        if not skill:
            return []

        suggestions = []
        if skill.false_positive_count > 3:
            suggestions.append("High FP rate — tighten validation rules or add FP patterns")
        if skill.success_rate < 0.1 and skill.success_count + skill.failure_count > 10:
            suggestions.append("Low success rate — review heuristics and payload effectiveness")
        if not skill.validation_rules:
            suggestions.append("No validation rules — add evidence checks to reduce FPs")
        if not skill.payloads:
            suggestions.append("No payloads — add test payloads for active testing")
        return suggestions
