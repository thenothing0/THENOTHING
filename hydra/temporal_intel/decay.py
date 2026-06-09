"""
DecayAnalyzer + TemporalDecayFinding (Phase O).

Detects entities that were once active but have gone quiet — stale capabilities, adapters,
plugins, and verification methods — and emits advisory `TemporalDecayFinding`s ranked by
severity. Staleness is measured in elapsed buckets since the entity's last event relative to
the injected `now`, so it is fully deterministic. Advisory only — suggests, never acts.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

from hydra.temporal_intel.context import TemporalContext
from hydra.temporal_intel.util import DEFAULT_BUCKET_SECONDS, DEFAULT_WINDOW

# Domains whose decay is operationally meaningful.
DECAY_DOMAINS = ("capability", "adapter", "plugin", "verification")


@dataclass
class TemporalDecayFinding:
    entity: str
    type: str                 # the domain (capability/adapter/plugin/verification)
    severity: str             # high / medium / low
    confidence: float         # 0..1, from observed evidence volume
    rationale: str
    suggested_action: str
    stale_buckets: int
    last_seen: float

    def to_dict(self) -> Dict:
        return {"entity": self.entity, "type": self.type, "severity": self.severity,
                "confidence": self.confidence, "rationale": self.rationale,
                "suggested_action": self.suggested_action,
                "stale_buckets": self.stale_buckets, "last_seen": self.last_seen}


class DecayAnalyzer:
    def __init__(self, context: Optional[TemporalContext] = None,
                 bucket_seconds: float = DEFAULT_BUCKET_SECONDS, window: int = DEFAULT_WINDOW):
        self.ctx = (context or TemporalContext()).load()
        self.bucket_seconds = bucket_seconds
        self.window = window

    @staticmethod
    def _severity(stale_buckets: int, window: int) -> Optional[str]:
        if stale_buckets > 0.66 * window:
            return "high"
        if stale_buckets > 0.33 * window:
            return "medium"
        if stale_buckets > 0.10 * window:
            return "low"
        return None       # recently active → not decaying

    def domain_decay(self, domain: str, now: Optional[float] = None) -> List[TemporalDecayFinding]:
        ref = self.ctx.now(now)
        last_seen = self.ctx.last_seen(domain)
        counts: Dict[str, int] = {}
        for e in self.ctx.events(domain):
            counts[e.entity] = counts.get(e.entity, 0) + 1
        out: List[TemporalDecayFinding] = []
        for entity in sorted(last_seen):
            stale_buckets = int(max(0.0, ref - last_seen[entity]) // self.bucket_seconds)
            sev = self._severity(stale_buckets, self.window)
            if sev is None:
                continue
            n = counts.get(entity, 0)
            confidence = round(min(1.0, n / 10.0), 4)   # more history ⇒ more confident
            out.append(TemporalDecayFinding(
                entity=entity, type=domain, severity=sev, confidence=confidence,
                rationale=(f"no {domain} activity for {stale_buckets} buckets "
                           f"(~{int(self.bucket_seconds)}s each); {n} prior events"),
                suggested_action=f"review whether '{entity}' is still relevant or needs re-exercising",
                stale_buckets=stale_buckets, last_seen=last_seen[entity]))
        order = {"high": 0, "medium": 1, "low": 2}
        out.sort(key=lambda f: (order[f.severity], -f.stale_buckets, f.entity))
        return out

    def report(self, now: Optional[float] = None) -> Dict:
        findings: List[Dict] = []
        for d in DECAY_DOMAINS:
            findings.extend(f.to_dict() for f in self.domain_decay(d, now))
        # Global severity ranking across all domains (deterministic tie-breaks).
        order = {"high": 0, "medium": 1, "low": 2}
        findings.sort(key=lambda f: (order[f["severity"]], -f["stale_buckets"],
                                     f["type"], f["entity"]))
        by_sev = {s: sum(1 for f in findings if f["severity"] == s)
                  for s in ("high", "medium", "low")}
        return {"decay_findings": findings, "count": len(findings), "by_severity": by_sev,
                "advisory": True}
