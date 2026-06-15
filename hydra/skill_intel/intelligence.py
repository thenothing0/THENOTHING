"""
SkillGraphIntelligence (Phase R) — the unified skill-intelligence read surface.

Composes the skill graph / dependencies / composition / bundles / effectiveness / coverage / gaps /
marketplace / advisor over ONE shared SkillContext (which reuses the Phase-P OffensiveIntelligence
load-once). Read-only, deterministic, advisory, NON-executing; promotion.py / confidence.py / the
canonical wiki are untouched. Skills never execute, never modify capability/promotion/confidence
state, and never become a canonical source.
"""

from __future__ import annotations

from typing import Dict, Optional

from hydra.skill_intel.advisor import SkillAdvisor
from hydra.skill_intel.bundles import SkillBundles
from hydra.skill_intel.composition import SkillComposition
from hydra.skill_intel.context import SkillContext
from hydra.skill_intel.coverage import SkillCoverageAnalyzer
from hydra.skill_intel.dependencies import SkillDependencyAnalyzer
from hydra.skill_intel.effectiveness import SkillEffectivenessAnalyzer
from hydra.skill_intel.gaps import SkillGapAnalyzer
from hydra.skill_intel.marketplace import SkillMarketplace
from hydra.skill_intel.skill_graph import SkillGraph
from hydra.skill_intel.util import SKILL_SCORING_VERSION, mean


class SkillGraphIntelligence:
    def __init__(self, cc: Optional[SkillContext] = None):
        self.cc = cc or SkillContext()
        self.graph = SkillGraph(self.cc)
        self.deps = SkillDependencyAnalyzer(self.cc, self.graph)
        self.comp = SkillComposition(self.cc, self.graph)
        self.bundles = SkillBundles(self.cc)
        self.effectiveness = SkillEffectivenessAnalyzer(self.cc)
        self.coverage = SkillCoverageAnalyzer(self.cc)
        self.gaps = SkillGapAnalyzer(self.cc)
        self.marketplace = SkillMarketplace(self.cc)
        self.advisor = SkillAdvisor(self.cc)

    # ── individual views ───────────────────────────────────────────────────────
    def skill_graph(self, now: Optional[float] = None) -> Dict:
        out = dict(self.graph.build())
        out.update(self.comp.report())
        out["reference_time"] = self.cc.now(now)
        return out

    def skill_dependencies(self, now: Optional[float] = None) -> Dict:
        out = self.deps.report()
        out["reference_time"] = self.cc.now(now)
        return out

    def skill_bundles(self, now: Optional[float] = None) -> Dict:
        out = self.bundles.report()
        out["reference_time"] = self.cc.now(now)
        return out

    def skill_effectiveness(self, skill_id: str = "", now: Optional[float] = None) -> Dict:
        if skill_id:
            r = self.effectiveness.get(skill_id)
            out = r or {"skill_id": skill_id, "error": "unknown skill", "advisory": True}
        else:
            out = self.effectiveness.report()
        out["reference_time"] = self.cc.now(now)
        return out

    def skill_coverage(self, now: Optional[float] = None) -> Dict:
        out = self.coverage.report()
        out["reference_time"] = self.cc.now(now)
        return out

    def skill_gaps(self, now: Optional[float] = None) -> Dict:
        out = self.gaps.report()
        out["reference_time"] = self.cc.now(now)
        return out

    def skill_marketplace(self, now: Optional[float] = None) -> Dict:
        out = self.marketplace.report()
        out["reference_time"] = self.cc.now(now)
        return out

    # ── health & summary ────────────────────────────────────────────────────────
    def skill_health(self, now: Optional[float] = None) -> Dict:
        ref = self.cc.now(now)
        rows = self.effectiveness.rank()
        total = len(rows)
        if total == 0:
            return {"skill_health_score": None, "status": "no_skill_data",
                    "reference_time": ref, "advisory": True}
        effs = [r["effectiveness"] for r in rows if r["effectiveness"] is not None]
        mean_eff = mean(effs) if effs else 0.0
        cap_cov = self.coverage.capability_coverage()["coverage_pct"] / 100.0
        g = self.graph.build()
        edges = g["dependency_edges"] + g["composition_edges"]
        connected = {e["from"] for e in edges} | {e["to"] for e in edges}
        connectivity = len(connected) / total if total else 0.0
        score = max(0.0, min(100.0, 100.0 * (0.5 * mean_eff + 0.3 * cap_cov + 0.2 * connectivity)))
        return {
            "skill_health_score": round(score, 2),
            "status": "healthy" if score >= 60 else ("watch" if score >= 40 else "degrading"),
            "mean_skill_effectiveness": round(mean_eff, 4),
            "capability_coverage_pct": round(100 * cap_cov, 1),
            "graph_connectivity": round(connectivity, 4), "skills": total,
            "dependency_edges": g["dependency_edge_count"],
            "composition_edges": g["composition_edge_count"],
            "total_events": self.cc.total_events(),
            "data_mode": "learning" if self.cc.total_events() > 0 else "catalog_only",
            "reference_time": ref, "advisory": True,
        }

    def skill_summary(self, now: Optional[float] = None) -> Dict:
        g = self.graph.build()
        gaps = self.gaps.report()
        return {
            "skill_health": self.skill_health(now),
            "graph": {"nodes": g["node_count"], "dependency_edges": g["dependency_edge_count"],
                      "composition_edges": g["composition_edge_count"]},
            "top_skills": self.effectiveness.rank()[:5],
            "bundles": [{"bundle_id": b["bundle_id"], "skills": b["skill_count"],
                         "effectiveness": b["effectiveness"]} for b in self.bundles.bundles()],
            "coverage": self.coverage.capability_coverage(),
            "critical_skills": self.deps.critical_skills(top=5),
            "gaps": {"uncovered_capabilities": gaps["uncovered_count"],
                     "weak_skills": gaps["weak_skill_count"]},
            "recommendations": self.advisor.recommendations(limit=5),
            "scoring_version": SKILL_SCORING_VERSION, "total_events": self.cc.total_events(),
            "reference_time": self.cc.now(now), "advisory": True,
        }
