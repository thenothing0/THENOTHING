"""
CampaignModel + CampaignContext (Phase Q).

The 12 attack-tactic phases are declarative KNOWLEDGE OBJECTS mapped to Hydra capability categories.
Post-exploitation tactics are MODEL-ONLY: `hydra_capability_coverage="none"`, `advisory_model_only=True`,
zero capabilities — Hydra provides no capability and no execution for them (NON-executing guard).

CampaignContext is the load-once shared substrate: it wraps ONE Phase-P OffensiveIntelligence (which
holds one load-once OffensiveContext and memoizes its analyzers) plus a few cached derived views, so
every campaign analyzer shares it and Phase Q adds only O(C+D) on cached data. Store-free, deterministic,
advisory, NON-executing; promotion.py / confidence.py / the canonical wiki are untouched.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

# Ordered 12 tactic phases: (phase, order, hydra_categories, coverage). Empty categories ⇒ model-only.
_PHASES = [
    ("recon",                 1, ["reconnaissance"],             "full"),
    ("enumeration",           2, ["reconnaissance", "web", "api"], "full"),
    ("initial_access",        3, ["web", "api", "cloud"],        "partial"),
    ("execution",             4, ["verification"],               "partial"),
    ("persistence",           5, [],                             "none"),
    ("privilege_escalation",  6, [],                             "none"),
    ("defense_evasion",       7, [],                             "none"),
    ("credential_access",     8, ["secrets", "source_code"],     "partial"),
    ("discovery",             9, ["reconnaissance", "cloud"],    "full"),
    ("lateral_movement",     10, [],                             "none"),
    ("collection",           11, [],                             "none"),
    ("exfiltration",         12, [],                             "none"),
]

# Post-exploitation tactics Hydra deliberately does NOT cover (modeled for completeness only).
POST_EXPLOITATION = frozenset({
    "persistence", "privilege_escalation", "defense_evasion",
    "lateral_movement", "collection", "exfiltration",
})


@dataclass
class CampaignPhase:
    phase: str
    order: int
    hydra_categories: List[str]
    hydra_capability_coverage: str          # full | partial | none
    advisory_model_only: bool
    capabilities: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {"phase": self.phase, "order": self.order,
                "hydra_categories": self.hydra_categories,
                "hydra_capability_coverage": self.hydra_capability_coverage,
                "advisory_model_only": self.advisory_model_only,
                "capabilities": self.capabilities,
                "capability_count": len(self.capabilities), "advisory": True}


class CampaignContext:
    """Load-once shared substrate over ONE Phase-P OffensiveIntelligence + cached derived views."""

    def __init__(self, offensive=None):
        from hydra.offensive_intel.intelligence import OffensiveIntelligence
        self.oi = offensive or OffensiveIntelligence()
        self.ctx = self.oi.ctx
        self.engine = self.oi.engine
        self._eff_map = None
        self._skill_map = None
        self._redundant = None
        self._owner_plugin = None

    # ── cached reused views (compute at most once each) ──────────────────────────
    def catalog(self):
        return self.ctx.catalog()

    def graph(self):
        return self.ctx.graph()

    def owner_of(self) -> Dict[str, Optional[str]]:
        return self.ctx.owner_of()

    def eff_map(self) -> Dict:
        if self._eff_map is None:
            self._eff_map = self.engine.as_map()
        return self._eff_map

    def skill_map(self) -> List[Dict]:
        if self._skill_map is None:
            self._skill_map = self.oi.skills.skill_map()
        return self._skill_map

    def redundant_pairs(self) -> List[Dict]:
        if self._redundant is None:
            self._redundant = self.oi.overlap.redundant_pairs(threshold=0.6, limit=100000)
        return self._redundant

    def owner_plugin(self) -> Dict[str, str]:
        if self._owner_plugin is None:
            try:
                from hydra.plugins.plugin_registry import PluginRegistry
                self._owner_plugin = PluginRegistry().capability_owner_plugin()
            except Exception:
                self._owner_plugin = {}
        return self._owner_plugin

    def now(self, injected: Optional[float] = None) -> float:
        return self.ctx.now(injected)

    def total_events(self) -> int:
        return self.ctx.total_events()


class CampaignModel:
    def __init__(self, cc: Optional[CampaignContext] = None):
        self.cc = cc or CampaignContext()
        self._phases: Optional[List[CampaignPhase]] = None

    def phases(self) -> List[CampaignPhase]:
        if self._phases is not None:
            return self._phases
        by_cat: Dict[str, List[str]] = {}
        for c in self.cc.catalog().all():
            by_cat.setdefault(c.category, []).append(c.capability_id)
        out: List[CampaignPhase] = []
        for name, order, cats, coverage in _PHASES:
            model_only = name in POST_EXPLOITATION
            caps = [] if model_only else sorted({cid for cc in cats for cid in by_cat.get(cc, [])})
            out.append(CampaignPhase(
                phase=name, order=order, hydra_categories=cats,
                hydra_capability_coverage=("none" if model_only else coverage),
                advisory_model_only=model_only, capabilities=caps))
        out.sort(key=lambda p: p.order)
        self._phases = out
        return out

    def get(self, phase: str) -> Optional[CampaignPhase]:
        return next((p for p in self.phases() if p.phase == phase), None)

    def report(self) -> Dict:
        phases = self.phases()
        return {"phases": [p.to_dict() for p in phases], "phase_count": len(phases),
                "hydra_covered_phases": [p.phase for p in phases if not p.advisory_model_only],
                "model_only_phases": [p.phase for p in phases if p.advisory_model_only],
                "advisory": True}
