"""
TrendAnalyzer + MomentumAnalyzer (Phase O).

Classify each entity's activity over time as rising / stable / declining (TrendAnalyzer) and
quantify growth/decline momentum + acceleration (MomentumAnalyzer), per domain
(capability / adapter / agent / plugin / source / verification). Deterministic and explainable:
every verdict carries the slope, momentum, bucket series, and counts that produced it. O(E).
"""

from __future__ import annotations

from typing import Dict, List, Optional

from hydra.temporal_intel.context import TemporalContext
from hydra.temporal_intel.util import (
    DEFAULT_BUCKET_SECONDS,
    DEFAULT_WINDOW,
    acceleration,
    classify_trend,
    momentum,
    slope,
)

# Domains exposed as first-class trend surfaces (others remain queryable via `domain=`).
TREND_DOMAINS = ("capability", "adapter", "agent", "plugin", "source", "verification")


class TrendAnalyzer:
    def __init__(self, context: Optional[TemporalContext] = None,
                 bucket_seconds: float = DEFAULT_BUCKET_SECONDS, window: int = DEFAULT_WINDOW):
        self.ctx = (context or TemporalContext()).load()
        self.bucket_seconds = bucket_seconds
        self.window = window

    def _series(self, domain: str, now: float) -> Dict[str, List[float]]:
        return self.ctx.bucketed(domain, now, self.bucket_seconds, self.window)

    def domain_trends(self, domain: str, now: Optional[float] = None) -> List[Dict]:
        ref = self.ctx.now(now)
        series = self._series(domain, ref)
        out = []
        for entity in sorted(series):
            ys = series[entity]
            total = round(sum(ys), 4)
            out.append({
                "entity": entity, "domain": domain,
                "direction": classify_trend(ys),
                "slope": round(slope(ys), 6),
                "momentum": momentum(ys),
                "total_activity": total,
                "recent_activity": round(sum(ys[-max(1, self.window // 6):]), 4),
                "series": [round(y, 4) for y in ys],
            })
        # Deterministic order: strongest risers first, then by entity.
        out.sort(key=lambda d: (-d["slope"], -d["total_activity"], d["entity"]))
        return out

    def trends(self, now: Optional[float] = None) -> Dict[str, List[Dict]]:
        return {d: self.domain_trends(d, now) for d in TREND_DOMAINS}

    def rising(self, domain: str, now: Optional[float] = None) -> List[Dict]:
        return [t for t in self.domain_trends(domain, now) if t["direction"] == "rising"]

    def declining(self, domain: str, now: Optional[float] = None) -> List[Dict]:
        return [t for t in self.domain_trends(domain, now) if t["direction"] == "declining"]

    def emerging(self, domain: str = "capability", now: Optional[float] = None,
                 limit: int = 10) -> List[Dict]:
        """Rising entities whose activity is concentrated in the recent window (new growth)."""
        ref = self.ctx.now(now)
        series = self._series(domain, ref)
        rows = []
        for entity in series:
            ys = series[entity]
            half = self.window // 2
            older, recent = sum(ys[:half]), sum(ys[half:])
            if recent > older and recent > 0:
                rows.append({"entity": entity, "domain": domain,
                             "recent_activity": round(recent, 4),
                             "older_activity": round(older, 4),
                             "emergence": round(recent - older, 4)})
        rows.sort(key=lambda d: (-d["emergence"], d["entity"]))
        return rows[:limit]

    def declining_entities(self, domain: str = "capability", now: Optional[float] = None,
                           limit: int = 10) -> List[Dict]:
        ref = self.ctx.now(now)
        series = self._series(domain, ref)
        rows = []
        for entity in series:
            ys = series[entity]
            half = self.window // 2
            older, recent = sum(ys[:half]), sum(ys[half:])
            if older > recent:
                rows.append({"entity": entity, "domain": domain,
                             "recent_activity": round(recent, 4),
                             "older_activity": round(older, 4),
                             "decline": round(older - recent, 4)})
        rows.sort(key=lambda d: (-d["decline"], d["entity"]))
        return rows[:limit]


class MomentumAnalyzer:
    def __init__(self, context: Optional[TemporalContext] = None,
                 bucket_seconds: float = DEFAULT_BUCKET_SECONDS, window: int = DEFAULT_WINDOW):
        self.ctx = (context or TemporalContext()).load()
        self.bucket_seconds = bucket_seconds
        self.window = window

    def domain_momentum(self, domain: str, now: Optional[float] = None) -> List[Dict]:
        ref = self.ctx.now(now)
        series = self.ctx.bucketed(domain, ref, self.bucket_seconds, self.window)
        out = []
        for entity in sorted(series):
            ys = series[entity]
            m = momentum(ys)
            a = acceleration(ys)
            out.append({
                "entity": entity, "domain": domain,
                "growth_momentum": m if m > 0 else 0.0,
                "decline_momentum": -m if m < 0 else 0.0,
                "acceleration": a if a > 0 else 0.0,
                "deceleration": -a if a < 0 else 0.0,
                "net_momentum": m,
            })
        out.sort(key=lambda d: (-d["net_momentum"], d["entity"]))
        return out

    def momentum(self, now: Optional[float] = None) -> Dict[str, List[Dict]]:
        return {d: self.domain_momentum(d, now) for d in TREND_DOMAINS}
