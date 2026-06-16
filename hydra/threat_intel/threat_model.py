"""
ThreatModel (Phase U) — synthesizes the unified Threat entities by fusing all seven layers.

A **Threat** is keyed by an ATT&CK tactic (Phase T) and fuses, deterministically and explainably:
  * techniques + coverage          (Phase T);
  * backing capabilities           (Phase T mapping → Phase P effectiveness);
  * skills + agents                (Phase R cap→skill, Phase P ownership);
  * campaign phases                (Phase Q, linked by SHARED CATEGORY — explained, never guessed);
  * adversary profiles             (Phase T, by shared techniques);
  * opportunity gap                (Phase S OpportunityScore of the backing capabilities);
  * temporal momentum / decay      (Phase O emerging vs declining);
  * federation consensus           (Phase N, guarded).
Out-of-scope / post-exploitation tactics are MODEL-ONLY threats (Hydra provides no capability and no
execution — `out_of_scope`, never scored as a fixable "high risk"). Clustering groups related threats
by shared capabilities (deterministic connected components). Read-only, advisory; O(C + D + T).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from hydra.threat_intel.context import ThreatContext
from hydra.threat_intel.util import (
    CLUSTER_JACCARD,
    W_COVERAGE_DEFICIT,
    W_DECAY,
    W_OPPORTUNITY_GAP,
    clamp01,
    jaccard,
    mean,
)


@dataclass
class Threat:
    threat_id: str                 # == ATT&CK tactic id (e.g. "TA0043")
    name: str
    model_only: bool               # out-of-scope / post-exploitation tactic
    techniques: List[str]
    in_scope_techniques: int
    covered: int
    weak: int
    uncovered: int
    fragile_techniques: int
    coverage_ratio: float
    capabilities: List[str]
    categories: List[str]
    skills: List[str]
    agents: List[str]
    campaign_phases: List[str]
    adversary_profiles: List[str]
    opportunity_gap: float
    emerging_capabilities: List[str]
    declining_capabilities: List[str]
    decay: float
    federation_confidence: float
    risk_score: Optional[float]
    risk_status: str
    components: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "threat_id": self.threat_id, "name": self.name,
            "advisory_model_only": self.model_only, "techniques": self.techniques,
            "in_scope_techniques": self.in_scope_techniques, "covered": self.covered,
            "weak": self.weak, "uncovered": self.uncovered,
            "fragile_techniques": self.fragile_techniques, "coverage_ratio": self.coverage_ratio,
            "capabilities": self.capabilities, "capability_count": len(self.capabilities),
            "categories": self.categories, "skills": self.skills, "agents": self.agents,
            "campaign_phases": self.campaign_phases, "adversary_profiles": self.adversary_profiles,
            "opportunity_gap": self.opportunity_gap,
            "emerging_capabilities": self.emerging_capabilities,
            "declining_capabilities": self.declining_capabilities, "decay": self.decay,
            "federation_confidence": self.federation_confidence,
            "risk_score": self.risk_score, "risk_status": self.risk_status,
            "risk_components": self.components, "advisory": True,
        }


class ThreatModel:
    def __init__(self, tc: Optional[ThreatContext] = None):
        self.tc = tc or ThreatContext()
        self._threats: Optional[List[Threat]] = None

    def _synthesize(self) -> List[Threat]:
        if self._threats is not None:
            return self._threats
        tc = self.tc
        mapping = tc.mapping()
        adv = tc.adversary()
        tcov = {r.technique_id: r for r in adv.techniques.rank()}
        opp = {o.opportunity_id: o.score for o in tc.opportunity().ranker.rank()}
        temporal = tc.temporal_signal()
        emerging, declining = temporal["emerging"], temporal["declining"]
        fed = tc.federation_signal()
        fed_conf = fed["confidence"]
        cap_to_skills = tc.cap_to_skills()
        owner = tc.owner_of()
        phases = [p for p in tc.campaign().model.phases() if not p.advisory_model_only]
        profiles = adv.profiles._rows()

        out: List[Threat] = []
        for tac in mapping.tactics():
            techs = mapping.techniques_for_tactic(tac.tactic_id)
            tech_ids = sorted(t.technique_id for t in techs)
            in_scope = [t for t in techs if not t.model_only]
            cov_rows = [tcov[t.technique_id] for t in in_scope if t.technique_id in tcov]
            covered = sum(1 for r in cov_rows if r.status == "covered")
            weak = sum(1 for r in cov_rows if r.status == "weak")
            uncovered = sum(1 for r in cov_rows if r.status == "uncovered")
            fragile = sum(1 for r in cov_rows if r.fragile)
            denom = len(in_scope) or 1
            coverage_ratio = round(covered / denom, 4) if in_scope else 0.0

            caps = sorted({c for r in cov_rows for c in r.capabilities})
            categories = sorted({cat for t in in_scope for cat in t.categories})
            skills = sorted({s for c in caps for s in cap_to_skills.get(c, [])})
            agents = sorted({owner[c] for c in caps if owner.get(c)})
            phase_ids = sorted({p.phase for p in phases if set(p.hydra_categories) & set(categories)})
            profs = sorted({p["profile_id"] for p in profiles
                            if set(p["techniques"]) & set(tech_ids)})

            opp_gap = round(mean([opp.get(c, 0.0) for c in caps]), 4) if caps else 0.0
            emg = sorted(c for c in caps if c in emerging)
            dec = sorted(c for c in caps if c in declining)
            decay = round(len(dec) / len(caps), 4) if caps else 0.0
            fconf = round(mean([fed_conf[c] for c in caps if c in fed_conf]), 4) \
                if any(c in fed_conf for c in caps) else 0.0

            if tac.advisory_model_only:
                risk_score: Optional[float] = None
                risk_status = "out_of_scope"
                components: Dict[str, float] = {}
            else:
                coverage_deficit = round(1.0 - coverage_ratio, 4)
                components = {
                    "coverage_deficit": round(W_COVERAGE_DEFICIT * coverage_deficit, 4),
                    "opportunity_gap": round(W_OPPORTUNITY_GAP * opp_gap, 4),
                    "decay": round(W_DECAY * decay, 4),
                }
                risk_score = round(clamp01(sum(components.values())), 4)
                risk_status = ("high" if risk_score >= 0.5 else
                               ("moderate" if risk_score >= 0.25 else "low"))

            out.append(Threat(
                threat_id=tac.tactic_id, name=tac.name, model_only=tac.advisory_model_only,
                techniques=tech_ids, in_scope_techniques=len(in_scope), covered=covered,
                weak=weak, uncovered=uncovered, fragile_techniques=fragile,
                coverage_ratio=coverage_ratio, capabilities=caps, categories=categories,
                skills=skills, agents=agents, campaign_phases=phase_ids, adversary_profiles=profs,
                opportunity_gap=opp_gap, emerging_capabilities=emg, declining_capabilities=dec,
                decay=decay, federation_confidence=fconf, risk_score=risk_score,
                risk_status=risk_status, components=components))
        out.sort(key=lambda t: (t.model_only, -(t.risk_score or -1.0), t.threat_id))
        self._threats = out
        return out

    # ── queries ──────────────────────────────────────────────────────────────────
    def threats(self) -> List[Threat]:
        return self._synthesize()

    def in_scope(self) -> List[Threat]:
        return [t for t in self._synthesize() if not t.model_only]

    def get(self, threat_id: str) -> Optional[Threat]:
        return next((t for t in self._synthesize() if t.threat_id == threat_id), None)

    # ── clustering (deterministic connected components by shared capabilities) ────
    def clusters(self) -> List[Dict]:
        threats = self.in_scope()
        capsets = {t.threat_id: set(t.capabilities) for t in threats}
        adj: Dict[str, set] = {t.threat_id: set() for t in threats}
        for i in range(len(threats)):
            for j in range(i + 1, len(threats)):
                a, b = threats[i].threat_id, threats[j].threat_id
                if jaccard(capsets[a], capsets[b]) >= CLUSTER_JACCARD:
                    adj[a].add(b)
                    adj[b].add(a)
        seen, clusters = set(), []
        for t in threats:
            if t.threat_id in seen:
                continue
            stack, comp = [t.threat_id], []
            while stack:
                n = stack.pop()
                if n in seen:
                    continue
                seen.add(n)
                comp.append(n)
                stack.extend(sorted(adj[n] - seen))
            comp = sorted(comp)
            shared_caps = sorted(set.intersection(*[capsets[c] for c in comp])) if len(comp) > 1 else \
                sorted(capsets[comp[0]])
            shared_skills = sorted(
                set.intersection(*[set(self.get(c).skills) for c in comp])) if len(comp) > 1 else \
                sorted(self.get(comp[0]).skills)
            clusters.append({
                "cluster_id": f"cluster_{comp[0]}", "threats": comp, "size": len(comp),
                "shared_capabilities": shared_caps, "shared_skills": shared_skills,
                "reason": (f"threats share ≥{int(CLUSTER_JACCARD * 100)}% of backing capabilities"
                           if len(comp) > 1 else "singleton (no strong capability overlap)"),
                "advisory": True})
        clusters.sort(key=lambda c: (-c["size"], c["cluster_id"]))
        return clusters

    def report(self, threat_id: str = "") -> Dict:
        if threat_id:
            t = self.get(threat_id)
            return (t.to_dict() if t else
                    {"threat_id": threat_id, "error": "unknown threat", "advisory": True})
        threats = self._synthesize()
        return {
            "threats": [t.to_dict() for t in threats], "count": len(threats),
            "in_scope": len(self.in_scope()),
            "model_only": [t.threat_id for t in threats if t.model_only],
            "advisory": True,
        }
