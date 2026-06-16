"""
AdversaryIntelligence (Phase T) — the unified adversary/ATT&CK read surface.

Composes the ATT&CK mapping / technique & tactic coverage / adversary profiles / gap analysis /
skill & capability mappers / advisor over ONE shared AdversaryContext (which reuses the Phase-P
OffensiveIntelligence load-once and threads it through Phase-S → Phase-Q/R; Phase-O contributes a
bounded guarded signal). Read-only, deterministic, advisory, NON-executing; promotion.py /
confidence.py / the canonical wiki are untouched.
"""

from __future__ import annotations

from typing import Dict, Optional

from hydra.adversary_intel.advisor import AdversaryAdvisor
from hydra.adversary_intel.adversary_profiles import AdversaryProfileModeler
from hydra.adversary_intel.capability_mapping import CapabilityTechniqueMapper
from hydra.adversary_intel.context import AdversaryContext
from hydra.adversary_intel.gap_analysis import AttackGapAnalyzer
from hydra.adversary_intel.skill_mapping import SkillTechniqueMapper
from hydra.adversary_intel.tactic_coverage import TacticCoverageAnalyzer
from hydra.adversary_intel.technique_coverage import TechniqueCoverageAnalyzer
from hydra.adversary_intel.util import ADVERSARY_SCORING_VERSION, W_EFFECT, W_TACTIC, W_TECHNIQUE, mean


class AdversaryIntelligence:
    def __init__(self, ac: Optional[AdversaryContext] = None):
        self.ac = ac or AdversaryContext()
        self.techniques = TechniqueCoverageAnalyzer(self.ac)
        self.tactics = TacticCoverageAnalyzer(self.ac, self.techniques)
        self.profiles = AdversaryProfileModeler(self.ac, self.techniques)
        self.gaps = AttackGapAnalyzer(self.ac, self.techniques, self.tactics)
        self.skills = SkillTechniqueMapper(self.ac)
        self.capabilities = CapabilityTechniqueMapper(self.ac)
        self.advisor = AdversaryAdvisor(self.ac, self.gaps)

    # ── individual views ───────────────────────────────────────────────────────
    def attack_tactics(self, now: Optional[float] = None) -> Dict:
        out = self.tactics.report()
        out["reference_time"] = self.ac.now(now)
        return out

    def attack_techniques(self, technique_id: str = "", tactic_id: str = "",
                          now: Optional[float] = None) -> Dict:
        out = self.techniques.report(technique_id=technique_id, tactic_id=tactic_id)
        out["reference_time"] = self.ac.now(now)
        return out

    def attack_gaps(self, now: Optional[float] = None) -> Dict:
        out = self.gaps.report()
        out["reference_time"] = self.ac.now(now)
        return out

    def attack_profiles(self, profile: str = "", now: Optional[float] = None) -> Dict:
        out = self.profiles.report(profile_id=profile)
        out["reference_time"] = self.ac.now(now)
        return out

    def attack_skills(self, now: Optional[float] = None) -> Dict:
        out = self.skills.report()
        out["reference_time"] = self.ac.now(now)
        return out

    def attack_capabilities(self, limit: int = 25, now: Optional[float] = None) -> Dict:
        out = self.capabilities.report(limit=limit)
        out["reference_time"] = self.ac.now(now)
        return out

    # ── health & summary ────────────────────────────────────────────────────────
    def attack_health(self, now: Optional[float] = None) -> Dict:
        ref = self.ac.now(now)
        techs = self.techniques.rank()
        in_scope = [t for t in techs if not t.model_only]
        if not in_scope:
            return {"adversary_health_score": None, "status": "no_attack_data",
                    "total_events": 0, "reference_time": ref, "advisory": True}
        covered = [t for t in in_scope if t.status == "covered"]
        technique_coverage = len(covered) / len(in_scope)
        tac_rows = [t for t in self.tactics.report()["tactics"] if not t["advisory_model_only"]]
        tactic_coverage = mean([t["coverage_pct"] / 100.0 for t in tac_rows]) if tac_rows else 0.0
        mean_eff = mean([t.best_effectiveness for t in covered]) if covered else 0.0
        score = max(0.0, min(100.0, 100.0 * (
            W_TECHNIQUE * technique_coverage + W_TACTIC * tactic_coverage + W_EFFECT * mean_eff)))
        return {
            "adversary_health_score": round(score, 2),
            "status": "healthy" if score >= 60 else ("watch" if score >= 40 else "degrading"),
            "technique_coverage": round(technique_coverage, 4),
            "tactic_coverage": round(tactic_coverage, 4),
            "mean_covered_effectiveness": round(mean_eff, 4),
            "covered_techniques": len(covered), "in_scope_techniques": len(in_scope),
            "hydra_covered_tactics": len(tac_rows),
            "model_only_tactics": sum(1 for t in self.tactics.report()["tactics"]
                                      if t["advisory_model_only"]),
            "total_events": self.ac.total_events(),
            "data_mode": "learning" if self.ac.total_events() > 0 else "catalog_only",
            "reference_time": ref, "advisory": True,
        }

    def adversary_summary(self, now: Optional[float] = None) -> Dict:
        tac = self.tactics.report()
        tech = self.techniques.report()
        gaps = self.gaps.report()
        prof = self.profiles.report()
        return {
            "adversary_health": self.attack_health(now),
            "tactics": {"hydra_covered": tac["hydra_covered_tactics"],
                        "model_only": tac["model_only_tactics"],
                        "strongest": tac["strongest_tactics"][:3]},
            "techniques": {"by_status": tech["by_status"], "in_scope": tech["in_scope"]},
            "best_supported_profiles": prof["best_supported"],
            "gaps": {"weak_techniques": gaps["weak_technique_count"],
                     "uncovered_techniques": gaps["uncovered_technique_count"],
                     "weak_tactics": gaps["weak_tactic_count"],
                     "top_opportunities": gaps["opportunities_improving_coverage"][:5]},
            "top_capabilities": self.capabilities.report()["top"],
            "recommendations": self.advisor.recommendations(limit=5),
            "scoring_version": ADVERSARY_SCORING_VERSION,
            "total_events": self.ac.total_events(),
            "reference_time": self.ac.now(now), "advisory": True,
        }
