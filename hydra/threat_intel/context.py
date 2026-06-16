"""
ThreatContext (Phase U) — load-once shared substrate for threat-intelligence knowledge fusion.

Phase U is a FUSION layer: it reasons over Hydra's existing knowledge, it never collects live
intelligence, never executes, never attacks. ThreatContext wraps ONE Phase-P OffensiveIntelligence
and builds ONE Phase-T AdversaryIntelligence over it — and because the Phase-T AdversaryContext
already threads that same `oi` through Phase-S OpportunityIntelligence (→ Phase-Q CampaignIntelligence
+ Phase-R SkillGraphIntelligence), P/Q/R/S/T all share a single OffensiveContext load (no duplicate
scans). The Phase-O temporal signal and the Phase-N federation signal come from their own derived
stores; both are loaded lazily, memoized once, and fully guarded (cold-start / offline → empty,
never an error).

Store-free (no embedded datastore in this package), read-only, deterministic, advisory,
NON-executing; promotion.py / confidence.py / the canonical wiki are untouched.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Set


class ThreatContext:
    def __init__(self, offensive=None):
        from hydra.offensive_intel.intelligence import OffensiveIntelligence
        self.oi = offensive or OffensiveIntelligence()
        self.ctx = self.oi.ctx
        self.engine = self.oi.engine
        self._adversary = None
        self._eff_map: Optional[Dict] = None
        self._temporal: Optional[Dict[str, Set[str]]] = None
        self._federation: Optional[Dict] = None

    # ── reused intelligence layers (all share THIS oi) ───────────────────────────
    def adversary(self):
        """Phase-T AdversaryIntelligence over an AdversaryContext that shares this oi (→ S/Q/R)."""
        if self._adversary is None:
            from hydra.adversary_intel.context import AdversaryContext
            from hydra.adversary_intel.intelligence import AdversaryIntelligence
            self._adversary = AdversaryIntelligence(AdversaryContext(self.oi))
        return self._adversary

    def opportunity(self):
        """Phase-S OpportunityIntelligence (via the shared Phase-T AdversaryContext)."""
        return self.adversary().ac.opportunity()

    def campaign(self):
        """Phase-Q CampaignIntelligence (via the shared chain)."""
        return self.adversary().ac.campaign()

    def skill(self):
        """Phase-R SkillGraphIntelligence (via the shared chain)."""
        return self.adversary().ac.skill()

    def mapping(self):
        """The Phase-T declarative ATT&CK knowledge object (shares the catalog)."""
        return self.adversary().ac.mapping()

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
        return self.adversary().ac.cap_to_skills()

    # ── cross-store derived signals (Phase O / Phase N; lazy + guarded) ──────────
    def temporal_signal(self) -> Dict[str, Set[str]]:
        """Phase-O momentum: emerging vs declining capability ids. Defensive — absent store / error
        yields empty sets (cold-start), so determinism + rebuild-identity hold."""
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

    def federation_signal(self) -> Dict:
        """Phase-N consensus: per-capability federation confidence + the mean, plus peer demand
        (metadata only). Defensive — offline / empty ledger / error yields neutral defaults (no
        penalty for absence), so determinism holds and an absent federation never drags scores."""
        if self._federation is None:
            confidence: Dict[str, float] = {}
            demand: Dict[str, int] = {}
            mean_confidence = 0.0
            peers = 0
            try:
                from hydra.federation.consensus import ConsensusEngine
                from hydra.federation.intelligence import IntelligenceMesh
                mesh = IntelligenceMesh()
                for p in mesh.capability_popularity():
                    cid = p.get("capability_id")
                    if cid:
                        demand[str(cid)] = int(p.get("peer_count", 0) or 0)
                cons = ConsensusEngine(mesh=mesh)
                rep = cons.consensus_report(top=100000)
                mean_confidence = float(rep.get("mean_federation_confidence", 0.0) or 0.0)
                for row in rep.get("top_consensus", []):
                    cid = row.get("capability_id")
                    if cid:
                        confidence[str(cid)] = float(row.get("federation_confidence", 0.0) or 0.0)
                peers = sum(1 for _ in mesh._digests()) and len(
                    {e.get("origin_peer_id", "") for e in mesh._digests()})
            except Exception:
                confidence, demand, mean_confidence, peers = {}, {}, 0.0, 0
            self._federation = {"confidence": confidence, "demand": demand,
                                "mean_confidence": mean_confidence, "peers": peers}
        return self._federation

    # ── access ────────────────────────────────────────────────────────────────────
    def now(self, injected: Optional[float] = None) -> float:
        return self.ctx.now(injected)

    def total_events(self) -> int:
        return self.ctx.total_events()
