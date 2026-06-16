"""
TechniqueCoverageAnalyzer (Phase T) — per-ATT&CK-technique coverage.

For each technique, resolves the supporting Hydra capabilities (via the AttackMapping) and scores
coverage from the Phase-P effectiveness engine:
  * `covered`    — ≥2 supporting capabilities AND best effectiveness ≥ threshold (robust);
  * `weak`       — capabilities exist but the best is below threshold OR there is a single provider
                   (`fragile` — coverage depends on one capability, the bottleneck insight from
                   Phase S applied to ATT&CK);
  * `uncovered`  — in-scope but no supporting capability;
  * `model_only` — out-of-scope / post-exploitation — Hydra provides no capability, never a defect.
Deterministic, read-only, advisory; O(T·C) bounded by the small static technique set.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

from hydra.adversary_intel.context import AdversaryContext
from hydra.adversary_intel.util import (
    COVERED,
    COVERED_EFFECTIVENESS,
    MODEL_ONLY,
    UNCOVERED,
    WEAK,
    mean,
)

_STATUS_ORDER = {COVERED: 0, WEAK: 1, UNCOVERED: 2, MODEL_ONLY: 3}


@dataclass
class TechniqueCoverage:
    technique_id: str
    name: str
    tactic_id: str
    status: str
    capabilities: List[str]
    capability_count: int
    best_effectiveness: float
    mean_effectiveness: float
    fragile: bool
    model_only: bool

    def to_dict(self) -> Dict:
        return {
            "technique_id": self.technique_id, "name": self.name, "tactic_id": self.tactic_id,
            "status": self.status, "capabilities": self.capabilities,
            "capability_count": self.capability_count,
            "best_effectiveness": self.best_effectiveness,
            "mean_effectiveness": self.mean_effectiveness,
            "fragile": self.fragile, "advisory_model_only": self.model_only, "advisory": True,
        }


class TechniqueCoverageAnalyzer:
    def __init__(self, ac: Optional[AdversaryContext] = None):
        self.ac = ac or AdversaryContext()
        self._cache: Optional[List[TechniqueCoverage]] = None

    def _compute(self) -> List[TechniqueCoverage]:
        if self._cache is not None:
            return self._cache
        emap = self.ac.eff_map()
        mapping = self.ac.mapping()
        rows: List[TechniqueCoverage] = []
        for t in mapping.techniques():
            if t.model_only:
                rows.append(TechniqueCoverage(t.technique_id, t.name, t.tactic_id, MODEL_ONLY,
                                              [], 0, 0.0, 0.0, False, True))
                continue
            caps = mapping.capabilities_for(t)
            effs = [emap[c].effectiveness for c in caps if c in emap]
            best = round(max(effs), 4) if effs else 0.0
            avg = round(mean(effs), 4) if effs else 0.0
            n = len(caps)
            fragile = n == 1                 # coverage depends on a single capability (bottleneck)
            if n == 0:
                status = UNCOVERED
            elif best < COVERED_EFFECTIVENESS or fragile:
                status = WEAK
            else:
                status = COVERED
            rows.append(TechniqueCoverage(t.technique_id, t.name, t.tactic_id, status,
                                          caps, n, best, avg, fragile, False))
        rows.sort(key=lambda r: (_STATUS_ORDER[r.status], -r.best_effectiveness, r.technique_id))
        self._cache = rows
        return rows

    def rank(self, limit: Optional[int] = None) -> List[TechniqueCoverage]:
        r = self._compute()
        return r[:limit] if limit else r

    def get(self, technique_id: str) -> Optional[TechniqueCoverage]:
        return next((r for r in self._compute() if r.technique_id == technique_id), None)

    def by_status(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for r in self._compute():
            out[r.status] = out.get(r.status, 0) + 1
        return dict(sorted(out.items()))

    def report(self, technique_id: str = "", tactic_id: str = "") -> Dict:
        rows = self._compute()
        if technique_id:
            r = self.get(technique_id)
            return (r.to_dict() if r else
                    {"technique_id": technique_id, "error": "unknown technique", "advisory": True})
        if tactic_id:
            rows = [r for r in rows if r.tactic_id == tactic_id]
        by_status = {}
        for r in rows:
            by_status[r.status] = by_status.get(r.status, 0) + 1
        in_scope = [r for r in rows if not r.model_only]
        return {
            "techniques": [r.to_dict() for r in rows], "count": len(rows),
            "in_scope": len(in_scope),
            "by_status": dict(sorted(by_status.items())),
            "covered": [r.technique_id for r in rows if r.status == COVERED],
            "weak": [r.technique_id for r in rows if r.status == WEAK],
            "uncovered": [r.technique_id for r in rows if r.status == UNCOVERED],
            "advisory": True,
        }
