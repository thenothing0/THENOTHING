"""
OffensiveIntelligence (Phase P) — the unified offensive read surface.

Composes the effectiveness / coverage / chains / overlap / gaps / skills / advisor analyzers over
ONE shared OffensiveContext (load-once, O(E)) and exposes the high-level views the MCP layer
serves. Read-only, deterministic, advisory; NON-executing; promotion.py / confidence.py / the
canonical wiki are untouched.
"""

from __future__ import annotations

from typing import Dict, Optional

from hydra.offensive_intel.advisor import OffensiveAdvisor
from hydra.offensive_intel.chains import AttackChainIntelligence
from hydra.offensive_intel.context import OffensiveContext
from hydra.offensive_intel.coverage import OffensiveCoverageAnalyzer
from hydra.offensive_intel.effectiveness import CapabilityEffectivenessEngine
from hydra.offensive_intel.gaps import OffensiveGapAnalyzer
from hydra.offensive_intel.overlap import OverlapAnalyzer
from hydra.offensive_intel.skills import SkillIntelligence
from hydra.offensive_intel.util import SCORING_VERSION, WEAK_EFFECTIVENESS, mean


class OffensiveIntelligence:
    def __init__(self, context: Optional[OffensiveContext] = None):
        self.ctx = (context or OffensiveContext()).load()
        self.engine = CapabilityEffectivenessEngine(self.ctx)
        self.coverage = OffensiveCoverageAnalyzer(self.ctx, self.engine)
        self.attack = AttackChainIntelligence(self.ctx, self.engine)
        self.overlap = OverlapAnalyzer(self.ctx, self.engine)
        self.gaps = OffensiveGapAnalyzer(self.ctx, self.engine)
        self.skills = SkillIntelligence(self.ctx, self.engine)
        self.advisor = OffensiveAdvisor(self.ctx, self.engine)

    # ── individual views ───────────────────────────────────────────────────────
    def offensive_effectiveness(self, capability_id: str = "",
                                now: Optional[float] = None) -> Dict:
        if capability_id:
            ce = self.engine.get(capability_id)
            return ce.to_dict() if ce else {
                "capability_id": capability_id, "error": "unknown capability", "advisory": True}
        ranked = self.engine.rank()
        return {"capabilities": [e.to_dict() for e in ranked], "count": len(ranked),
                "scoring_version": SCORING_VERSION,
                "top": [e.capability_id for e in ranked[:5]],
                "weakest": [e.capability_id for e in self.engine.weakest(5)],
                "underutilized": [e.capability_id for e in self.engine.underutilized(5)],
                "reference_time": self.ctx.now(now), "advisory": True}

    def offensive_coverage(self, category: str = "", now: Optional[float] = None) -> Dict:
        rep = self.coverage.report()
        if category:
            rep["category_coverage"] = [c for c in rep["category_coverage"]
                                        if c["category"] == category]
        rep["reference_time"] = self.ctx.now(now)
        return rep

    def attack_chains(self, target_type: str = "", limit: int = 10,
                      now: Optional[float] = None) -> Dict:
        out = self.attack.chains(target_type=target_type, limit=limit)
        out["reference_time"] = self.ctx.now(now)
        return out

    def offensive_overlap(self, now: Optional[float] = None) -> Dict:
        out = self.overlap.report()
        out["reference_time"] = self.ctx.now(now)
        return out

    def offensive_gaps(self, now: Optional[float] = None) -> Dict:
        out = self.gaps.report()
        out["reference_time"] = self.ctx.now(now)
        return out

    def offensive_skills(self, now: Optional[float] = None) -> Dict:
        out = self.skills.report()
        out["reference_time"] = self.ctx.now(now)
        return out

    # ── health & summary ────────────────────────────────────────────────────────
    def offensive_health(self, now: Optional[float] = None) -> Dict:
        ref = self.ctx.now(now)
        ranked = self.engine.rank()
        total = len(ranked)
        if total == 0:
            return {"offensive_health_score": None, "status": "no_offensive_data",
                    "total_events": 0, "reference_time": ref, "advisory": True}
        mean_eff = mean([e.effectiveness for e in ranked])
        learned = sum(1 for e in ranked if e.status == "learned")
        cov = self.coverage.category_coverage()
        weak_cats = sum(1 for c in cov if c["mean_effectiveness"] < WEAK_EFFECTIVENESS)
        blind = sum(1 for c in cov if c["verification_coverage_pct"] == 0.0)
        red = len(self.overlap.redundant_pairs(threshold=0.7, limit=100000))
        # Structural coverage quality: categories that are neither weak nor verification-blind.
        covered = sum(1 for c in cov
                      if c["mean_effectiveness"] >= WEAK_EFFECTIVENESS
                      and c["verification_coverage_pct"] > 0.0)
        coverage_quality = round(covered / len(cov), 4) if cov else 0.0
        # Deterministic bounded blend: effectiveness + structural coverage, rewards learned
        # evidence, lightly (capped) penalizes redundancy — interchangeable capabilities are
        # partly by design, so redundancy is an optimization signal, not a health defect.
        base = 100.0 * (0.7 * mean_eff + 0.3 * coverage_quality)
        learned_bonus = 8.0 * (learned / total)
        red_penalty = min(6.0, 0.03 * red)
        score = max(0.0, min(100.0, base + learned_bonus - red_penalty))
        return {
            "offensive_health_score": round(score, 2),
            "status": "healthy" if score >= 60 else ("watch" if score >= 40 else "degrading"),
            "mean_effectiveness": round(mean_eff, 4),
            "coverage_quality": coverage_quality,
            "capabilities_scored": total, "learned": learned, "prior_only": total - learned,
            "weak_categories": weak_cats, "verification_blindspots": blind,
            "redundant_pairs": red, "total_events": self.ctx.total_events(),
            "data_mode": "learning" if self.ctx.total_events() > 0 else "catalog_only",
            "reference_time": ref, "advisory": True,
        }

    def offensive_summary(self, now: Optional[float] = None) -> Dict:
        ranked = self.engine.rank()
        cov = self.coverage.category_coverage()
        return {
            "offensive_health": self.offensive_health(now),
            "top_capabilities": [e.to_dict() for e in ranked[:5]],
            "underutilized_capabilities": [e.capability_id for e in self.engine.underutilized(5)],
            "strongest_chains": self.attack.chains(limit=5)["chains"],
            "weak_categories": [c for c in cov
                                if c["mean_effectiveness"] < WEAK_EFFECTIVENESS][:5],
            "redundant_pairs": self.overlap.redundant_pairs(limit=5),
            "skill_bridge": self.skills.report()["skills"][:5],
            "recommendations": self.advisor.recommendations(limit=5),
            "scoring_version": SCORING_VERSION, "total_events": self.ctx.total_events(),
            "reference_time": self.ctx.now(now), "advisory": True,
        }
