"""Self-Evolving Skills Service (Phase 10.5).

Skills that improve themselves based on outcomes. Tracks skill effectiveness,
adjusts confidence weights, generates new skill variants from successful
patterns, and deprecates underperforming skills.
"""

import logging
import time
from typing import Any

from hydra.services.base import BaseService

logger = logging.getLogger("hydra.services.skill_evolution")

SKILL_CATEGORIES = (
    "recon", "scanning", "exploitation", "verification",
    "bypass", "chain", "reporting",
)

EVOLUTION_ACTIONS = (
    "boost", "penalize", "variant", "deprecate", "promote",
)


class SkillRecord:
    __slots__ = (
        "id", "name", "category", "confidence", "success_count",
        "failure_count", "total_uses", "last_used", "created_at",
        "parent_id", "deprecated",
    )

    def __init__(self, name: str, category: str = "scanning",
                 confidence: float = 0.5, parent_id: str = ""):
        self.id = f"sk-{int(time.time() * 1000)}"
        self.name = name
        self.category = category
        self.confidence = confidence
        self.success_count = 0
        self.failure_count = 0
        self.total_uses = 0
        self.last_used: float = 0
        self.created_at = time.time()
        self.parent_id = parent_id
        self.deprecated = False

    def to_dict(self) -> dict:
        return {
            "id": self.id, "name": self.name, "category": self.category,
            "confidence": round(self.confidence, 4),
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "total_uses": self.total_uses,
            "success_rate": round(
                self.success_count / max(self.total_uses, 1), 4),
            "last_used": self.last_used,
            "parent_id": self.parent_id,
            "deprecated": self.deprecated,
        }


class SkillEvolutionService(BaseService):
    """Self-evolving skill management and optimization."""

    def __init__(self, event_bus, data_dir=None):
        super().__init__(event_bus, data_dir)
        self._skills: dict[str, SkillRecord] = {}

    def register_skill(self, name: str, category: str = "scanning",
                       confidence: float = 0.5) -> dict:
        """Register a new skill for evolution tracking."""
        if category not in SKILL_CATEGORIES:
            return {"status": "error", "error": f"Unknown category: {category}"}
        skill = SkillRecord(name, category, confidence)
        self._skills[skill.id] = skill

        self._emit("skill_evolution.registered", {
            "skill_id": skill.id, "name": name, "category": category,
        })
        return {"status": "registered", **skill.to_dict()}

    def record_outcome(self, skill_id: str, success: bool,
                       context: dict | None = None) -> dict:
        """Record a skill usage outcome and evolve confidence."""
        skill = self._skills.get(skill_id)
        if not skill:
            return {"status": "error", "error": "Skill not found"}

        skill.total_uses += 1
        skill.last_used = time.time()

        if success:
            skill.success_count += 1
            skill.confidence = min(1.0, skill.confidence + 0.05)
        else:
            skill.failure_count += 1
            skill.confidence = max(0.0, skill.confidence - 0.08)

        if skill.confidence < 0.1 and skill.total_uses >= 5:
            skill.deprecated = True

        self._emit("skill_evolution.outcome", {
            "skill_id": skill_id, "success": success,
            "confidence": skill.confidence,
        })
        return {"status": "recorded", **skill.to_dict()}

    def create_variant(self, parent_id: str, name: str,
                       mutation: str = "") -> dict:
        """Create a skill variant from a successful parent."""
        parent = self._skills.get(parent_id)
        if not parent:
            return {"status": "error", "error": "Parent skill not found"}

        variant = SkillRecord(
            name, parent.category,
            confidence=parent.confidence * 0.8,
            parent_id=parent_id,
        )
        self._skills[variant.id] = variant

        self._emit("skill_evolution.variant_created", {
            "variant_id": variant.id, "parent_id": parent_id,
        })
        return {"status": "created", **variant.to_dict()}

    def rank_skills(self, category: str = "", limit: int = 10) -> list[dict]:
        """Rank skills by effectiveness."""
        skills = []
        for s in self._skills.values():
            if s.deprecated:
                continue
            if category and s.category != category:
                continue
            skills.append(s.to_dict())
        skills.sort(key=lambda x: x["confidence"], reverse=True)
        return skills[:limit]

    def get_deprecated(self) -> list[dict]:
        """List deprecated skills."""
        return [s.to_dict() for s in self._skills.values() if s.deprecated]

    def get_stats(self) -> dict[str, Any]:
        by_cat: dict[str, int] = {}
        active = deprecated = 0
        for s in self._skills.values():
            by_cat[s.category] = by_cat.get(s.category, 0) + 1
            if s.deprecated:
                deprecated += 1
            else:
                active += 1
        return {
            "total_skills": len(self._skills),
            "active": active,
            "deprecated": deprecated,
            "by_category": by_cat,
            "categories": list(SKILL_CATEGORIES),
            "evolution_actions": list(EVOLUTION_ACTIONS),
        }
