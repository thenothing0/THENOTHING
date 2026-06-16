"""
AdversaryContext (Phase T) — load-once shared substrate for adversary/ATT&CK intelligence.

Wraps ONE Phase-P OffensiveIntelligence and threads that SAME instance into the Phase-S
OpportunityIntelligence (which itself reuses the Phase-Q CampaignIntelligence and Phase-R
SkillGraphIntelligence), so P/Q/R/S/T all share one OffensiveContext load (no duplicate scans). The
Phase-O temporal signal is loaded lazily and fully guarded. The static ATT&CK knowledge object
(AttackMapping) shares the same catalog.

Store-free (no embedded datastore in this package), read-only, deterministic, advisory,
NON-executing; promotion.py / confidence.py / the canonical wiki are untouched.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Set


class AdversaryContext:
    def __init__(self, offensive=None):
        from hydra.offensive_intel.intelligence import OffensiveIntelligence
        self.oi = offensive or OffensiveIntelligence()
        self.ctx = self.oi.ctx
        self.engine = self.oi.engine
        self._opportunity = None
        self._mapping = None
        self._eff_map: Optional[Dict] = None
        self._cap_to_skills: Optional[Dict[str, List[str]]] = None
        self._temporal: Optional[Dict[str, Set[str]]] = None

    # ── static ATT&CK knowledge object (shares the catalog) ──────────────────────
    def mapping(self):
        if self._mapping is None:
            from hydra.adversary_intel.attack_mapping import AttackMapping
            self._mapping = AttackMapping(self.ctx)
        return self._mapping

    # ── reused intelligence layers (Phase S threads Q + R; all share THIS oi) ────
    def opportunity(self):
        """Phase-S OpportunityIntelligence over an OpportunityContext that shares this oi."""
        if self._opportunity is None:
            from hydra.opportunity_intel.context import OpportunityContext
            from hydra.opportunity_intel.intelligence import OpportunityIntelligence
            self._opportunity = OpportunityIntelligence(OpportunityContext(self.oi))
        return self._opportunity

    def skill(self):
        """Phase-R SkillGraphIntelligence (via the shared Phase-S OpportunityContext)."""
        return self.opportunity().oc.skill()

    def campaign(self):
        """Phase-Q CampaignIntelligence (via the shared Phase-S OpportunityContext)."""
        return self.opportunity().oc.campaign()

    # ── shared static views ──────────────────────────────────────────────────────
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

    def cap_to_skills(self) -> Dict[str, List[str]]:
        if self._cap_to_skills is None:
            self._cap_to_skills = self.opportunity().oc.cap_to_skills()
        return self._cap_to_skills

    # ── cross-store derived signal (Phase O; lazy + guarded) ─────────────────────
    def temporal_signal(self) -> Dict[str, Set[str]]:
        """Phase-O momentum: emerging vs declining capability ids. Defensive — any absent store /
        error yields empty sets (cold-start), so determinism + rebuild-identity hold."""
        if self._temporal is None:
            emerging: Set[str] = set()
            declining: Set[str] = set()
            try:
                from hydra.temporal_intel.intelligence import TemporalIntelligence
                ti = TemporalIntelligence()
                emerging = {str(r.get("entity")) for r in ti.emerging_capabilities() if r.get("entity")}
                declining = {str(r.get("entity")) for r in ti.declining_capabilities() if r.get("entity")}
            except Exception:
                emerging, declining = set(), set()
            self._temporal = {"emerging": emerging, "declining": declining}
        return self._temporal

    # ── access ────────────────────────────────────────────────────────────────────
    def now(self, injected: Optional[float] = None) -> float:
        return self.ctx.now(injected)

    def total_events(self) -> int:
        return self.ctx.total_events()
