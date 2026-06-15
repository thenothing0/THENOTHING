"""
SkillContext (Phase R) — load-once shared substrate for skill-graph intelligence.

This is a NEW package (`hydra.skill_intel`) — it does NOT modify the legacy `hydra.skills`
operational subsystem (SkillRegistry / yaml_loader / activation_engine), which it only reads
through the Phase-P skill bridge.

SkillContext wraps ONE Phase-P OffensiveIntelligence (which holds a single load-once
OffensiveContext and memoizes its analyzers) and exposes the skill map, the capability→skills
index, effectiveness, ownership and the capability dependency graph. Every skill analyzer shares
it, so Phase R adds only O(S + C + D) on cached data. Store-free, read-only, deterministic,
advisory, NON-executing; promotion.py / confidence.py / the canonical wiki are untouched.
"""

from __future__ import annotations

from typing import Dict, List, Optional


class SkillContext:
    def __init__(self, offensive=None):
        from hydra.offensive_intel.intelligence import OffensiveIntelligence
        self.oi = offensive or OffensiveIntelligence()
        self.ctx = self.oi.ctx
        self._skill_map: Optional[List[Dict]] = None
        self._by_id: Optional[Dict[str, Dict]] = None
        self._cap_to_skills: Optional[Dict[str, List[str]]] = None
        self._eff_map: Optional[Dict] = None

    # ── cached reused views (compute at most once each) ──────────────────────────
    def skill_map(self) -> List[Dict]:
        if self._skill_map is None:
            self._skill_map = self.oi.skills.skill_map()
        return self._skill_map

    def skills_by_id(self) -> Dict[str, Dict]:
        if self._by_id is None:
            self._by_id = {s["skill_id"]: s for s in self.skill_map()}
        return self._by_id

    def cap_to_skills(self) -> Dict[str, List[str]]:
        if self._cap_to_skills is None:
            m: Dict[str, set] = {}
            for s in self.skill_map():
                for c in s["capabilities"]:
                    m.setdefault(c, set()).add(s["skill_id"])
            self._cap_to_skills = {c: sorted(v) for c, v in m.items()}
        return self._cap_to_skills

    def eff_map(self) -> Dict:
        if self._eff_map is None:
            self._eff_map = self.oi.engine.as_map()
        return self._eff_map

    def graph(self):
        return self.ctx.graph()

    def catalog(self):
        return self.ctx.catalog()

    def owner_of(self) -> Dict[str, Optional[str]]:
        return self.ctx.owner_of()

    def now(self, injected: Optional[float] = None) -> float:
        return self.ctx.now(injected)

    def total_events(self) -> int:
        return self.ctx.total_events()
