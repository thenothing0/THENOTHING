"""
CampaignIntelligence (Phase Q) — the unified campaign read surface.

Composes the campaign model / skill bridge / playbooks / objective mapping / path generation /
strategy / simulation / advisor over ONE shared CampaignContext (which reuses the Phase-P
OffensiveIntelligence load-once). Read-only, deterministic, advisory, NON-executing; the
post-exploitation guard and promotion.py / confidence.py / canonical wiki are untouched.
"""

from __future__ import annotations

from typing import Dict, Optional

from hydra.campaigns.advisor import CampaignAdvisor
from hydra.campaigns.campaign_model import CampaignContext, CampaignModel
from hydra.campaigns.objective_mapping import OBJECTIVES, ObjectiveMapping, get_objective
from hydra.campaigns.path_generation import PathGeneration
from hydra.campaigns.playbooks import PlaybookGenerator
from hydra.campaigns.simulation import CampaignSimulator
from hydra.campaigns.strategy import StrategyComparator
from hydra.campaigns.util import CAMPAIGN_SCORING_VERSION, WEAK_EFFECTIVENESS, mean
from hydra.campaigns.workflow_graph import WorkflowGraph


class CampaignIntelligence:
    def __init__(self, cc: Optional[CampaignContext] = None):
        self.cc = cc or CampaignContext()
        self.model = CampaignModel(self.cc)
        self.workflow = WorkflowGraph(self.cc)
        self.playbooks = PlaybookGenerator(self.cc)
        self.objectives = ObjectiveMapping(self.cc)
        self.paths = PathGeneration(self.cc)
        self.strategy = StrategyComparator(self.cc)
        self.sim = CampaignSimulator(self.cc)
        self.advisor = CampaignAdvisor(self.cc)

    # ── individual views ───────────────────────────────────────────────────────
    def campaign_objectives(self, objective: str = "", now: Optional[float] = None) -> Dict:
        if objective:
            o = get_objective(objective)
            out = self.objectives.map_objective(o) if o else {
                "objective": objective, "error": "unknown objective", "advisory": True}
        else:
            out = {"objectives": [self.objectives.map_objective(o) for o in OBJECTIVES],
                   "count": len(OBJECTIVES), "advisory": True}
        out["reference_time"] = self.cc.now(now)
        return out

    def campaign_playbooks(self, playbook: str = "", now: Optional[float] = None) -> Dict:
        if playbook:
            pb = self.playbooks.get(playbook)
            out = pb or {"playbook_id": playbook, "error": "unknown playbook", "advisory": True}
        else:
            out = self.playbooks.summary()
        out["reference_time"] = self.cc.now(now)
        return out

    def campaign_paths(self, playbook: str = "", target_type: str = "",
                       limit: int = 10, now: Optional[float] = None) -> Dict:
        if playbook:
            pb = self.playbooks.get(playbook)
            if not pb:
                return {"playbook_id": playbook, "error": "unknown playbook",
                        "advisory": True, "reference_time": self.cc.now(now)}
            caps = [c["capability_id"] for c in pb["campaign_capabilities"]]
            out = {"playbook_id": playbook, "sequence": self.paths.sequence(caps),
                   "capability_graph": pb["capability_graph"], "skill_graph": pb["skill_graph"],
                   "advisory": True}
        else:
            out = self.paths.generate(target_type=target_type, limit=limit)
        out["reference_time"] = self.cc.now(now)
        return out

    def campaign_strategies(self, strategy_a: str = "", strategy_b: str = "",
                            now: Optional[float] = None) -> Dict:
        if not strategy_a or not strategy_b:
            rows = self.playbooks.summary()["playbooks"]
            if len(rows) >= 2:
                strategy_a, strategy_b = rows[0]["playbook_id"], rows[1]["playbook_id"]
        out = self.strategy.compare(strategy_a, strategy_b)
        out["reference_time"] = self.cc.now(now)
        return out

    def campaign_simulation(self, scenario: str = "remove_capability", subject: str = "",
                            now: Optional[float] = None) -> Dict:
        out = self.sim.simulate(scenario, subject)
        out["reference_time"] = self.cc.now(now)
        return out

    def campaign_gaps(self, now: Optional[float] = None) -> Dict:
        emap = self.cc.eff_map()
        weak_phases = []
        for p in self.model.phases():
            if p.advisory_model_only or not p.capabilities:
                continue
            effs = [emap[c].effectiveness for c in p.capabilities if c in emap]
            me = mean(effs) if effs else 0.0
            if me < WEAK_EFFECTIVENESS:
                weak_phases.append({"phase": p.phase, "mean_effectiveness": round(me, 4)})
        return {"weak_phases": weak_phases, "weak_phase_count": len(weak_phases),
                "model_only_phases": [p.phase for p in self.model.phases() if p.advisory_model_only],
                "offensive_gaps": self.cc.oi.offensive_gaps(now),
                "reference_time": self.cc.now(now), "advisory": True}

    # ── health & summary ────────────────────────────────────────────────────────
    def campaign_health(self, now: Optional[float] = None) -> Dict:
        ref = self.cc.now(now)
        phases = self.model.phases()
        covered = [p for p in phases if not p.advisory_model_only and p.capabilities]
        emap = self.cc.eff_map()
        phase_effs = []
        for p in covered:
            effs = [emap[c].effectiveness for c in p.capabilities if c in emap]
            if effs:
                phase_effs.append(mean(effs))
        mean_eff = mean(phase_effs) if phase_effs else 0.0
        playbooks = self.playbooks.all_playbooks()
        pb_eff = mean([p["effectiveness"] for p in playbooks]) if playbooks else 0.0
        coverage_q = round(len(covered) / 6.0, 4)         # 6 Hydra-covered tactic phases
        score = max(0.0, min(100.0, 100.0 * (0.5 * mean_eff + 0.3 * pb_eff + 0.2 * coverage_q)))
        return {
            "campaign_health_score": round(score, 2),
            "status": "healthy" if score >= 60 else ("watch" if score >= 40 else "degrading"),
            "mean_phase_effectiveness": round(mean_eff, 4),
            "mean_playbook_effectiveness": round(pb_eff, 4), "coverage_quality": coverage_q,
            "hydra_covered_phases": len(covered),
            "model_only_phases": sum(1 for p in phases if p.advisory_model_only),
            "playbooks": len(playbooks), "total_events": self.cc.total_events(),
            "data_mode": "learning" if self.cc.total_events() > 0 else "catalog_only",
            "reference_time": ref, "advisory": True,
        }

    def campaign_summary(self, now: Optional[float] = None) -> Dict:
        return {
            "campaign_health": self.campaign_health(now),
            "campaign_model": self.model.report(),
            "workflow_graph": self.workflow.build(),
            "playbooks": self.playbooks.summary()["playbooks"],
            "objectives": [{"objective": o["id"], "name": o["name"]} for o in OBJECTIVES],
            "recommendations": self.advisor.recommendations(limit=5),
            "scoring_version": CAMPAIGN_SCORING_VERSION, "total_events": self.cc.total_events(),
            "reference_time": self.cc.now(now), "advisory": True,
        }
