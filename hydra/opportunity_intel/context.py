"""
OpportunityContext (Phase S) — load-once shared substrate for opportunity intelligence.

Wraps ONE Phase-P OffensiveIntelligence (which holds a single load-once OffensiveContext and
memoizes its analyzers) and threads that SAME instance into the Phase-Q CampaignIntelligence and
the Phase-R SkillGraphIntelligence, so P/Q/R/S share one OffensiveContext load (no duplicate
scans). The Phase-O temporal signal and the Phase-N federation signal come from their own derived
stores; both are loaded lazily, memoized once, and fully guarded (cold-start / offline → empty,
never an error). Every opportunity analyzer shares this context, so Phase S adds only O(C + D) work
on cached data.

Store-free (no embedded datastore in this package — the underlying derived stores live in the
reused layers), read-only, deterministic, advisory, NON-executing; promotion.py / confidence.py /
the canonical wiki are untouched.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Set


class OpportunityContext:
    def __init__(self, offensive=None):
        from hydra.offensive_intel.intelligence import OffensiveIntelligence
        self.oi = offensive or OffensiveIntelligence()
        self.ctx = self.oi.ctx
        self.engine = self.oi.engine
        self._eff_map: Optional[Dict] = None
        self._skill = None
        self._campaign = None
        self._cap_to_skills: Optional[Dict[str, List[str]]] = None
        self._temporal: Optional[Dict[str, Set[str]]] = None
        self._federation: Optional[Dict[str, int]] = None

    # ── shared static views (single OffensiveContext load) ───────────────────────
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

    # ── reused intelligence layers (Phase Q / Phase R share THIS oi) ─────────────
    def skill(self):
        """Phase-R SkillGraphIntelligence over a SkillContext that shares this OffensiveIntelligence."""
        if self._skill is None:
            from hydra.skill_intel.context import SkillContext
            from hydra.skill_intel.intelligence import SkillGraphIntelligence
            self._skill = SkillGraphIntelligence(SkillContext(self.oi))
        return self._skill

    def campaign(self):
        """Phase-Q CampaignIntelligence over a CampaignContext that shares this OffensiveIntelligence."""
        if self._campaign is None:
            from hydra.campaigns.campaign_model import CampaignContext
            from hydra.campaigns.intelligence import CampaignIntelligence
            self._campaign = CampaignIntelligence(CampaignContext(self.oi))
        return self._campaign

    def cap_to_skills(self) -> Dict[str, List[str]]:
        if self._cap_to_skills is None:
            self._cap_to_skills = self.skill().cc.cap_to_skills()
        return self._cap_to_skills

    # ── cross-store derived signals (Phase O / Phase N; lazy + guarded) ──────────
    def temporal_signal(self) -> Dict[str, Set[str]]:
        """Phase-O momentum: capability ids that are emerging vs declining. Defensive — any absent
        store / error yields empty sets (cold-start), so determinism + rebuild-identity hold."""
        if self._temporal is None:
            emerging: Set[str] = set()
            declining: Set[str] = set()
            try:
                from hydra.temporal_intel.intelligence import TemporalIntelligence
                ti = TemporalIntelligence()
                emerging = {str(r.get("entity")) for r in ti.emerging_capabilities()
                            if r.get("entity")}
                declining = {str(r.get("entity")) for r in ti.declining_capabilities()
                             if r.get("entity")}
            except Exception:
                emerging, declining = set(), set()
            self._temporal = {"emerging": emerging, "declining": declining}
        return self._temporal

    def federation_signal(self) -> Dict[str, int]:
        """Phase-N demand: capability id → adopting-peer count across the federation (metadata only).
        Defensive — offline / empty ledger / error yields an empty map (no demand bonus)."""
        if self._federation is None:
            demand: Dict[str, int] = {}
            try:
                from hydra.federation.intelligence import IntelligenceMesh
                from hydra.federation.store import KnowledgeExchangeStore
                mesh = IntelligenceMesh(KnowledgeExchangeStore())
                for p in mesh.capability_popularity():
                    cid = p.get("capability_id")
                    if cid:
                        demand[str(cid)] = int(p.get("peer_count", 0) or 0)
            except Exception:
                demand = {}
            self._federation = demand
        return self._federation

    # ── access ────────────────────────────────────────────────────────────────────
    def now(self, injected: Optional[float] = None) -> float:
        return self.ctx.now(injected)

    def total_events(self) -> int:
        return self.ctx.total_events()
