"""
TemporalForecastEngine (Phase O).

Bounded, deterministic forecasts off the historical bucket series — moving-average base plus
least-squares linear slope, clamped to a sane range. NEVER stochastic; identical inputs ⇒
identical forecast. Forecasts future capability utilization, verification coverage, source
diversity, and plugin adoption. Advisory only.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from hydra.temporal_intel.context import TemporalContext
from hydra.temporal_intel.util import (
    DEFAULT_BUCKET_SECONDS,
    DEFAULT_WINDOW,
    forecast,
    slope,
)


class TemporalForecastEngine:
    def __init__(self, context: Optional[TemporalContext] = None,
                 bucket_seconds: float = DEFAULT_BUCKET_SECONDS, window: int = DEFAULT_WINDOW):
        self.ctx = (context or TemporalContext()).load()
        self.bucket_seconds = bucket_seconds
        self.window = window

    def _aggregate_series(self, domain: str, now: float) -> List[float]:
        """Sum all entities' per-bucket activity into one domain-level series."""
        series = self.ctx.bucketed(domain, now, self.bucket_seconds, self.window)
        agg = [0.0] * self.window
        for ys in series.values():
            for i, y in enumerate(ys):
                agg[i] += y
        return agg

    def domain_forecast(self, domain: str, now: Optional[float] = None,
                        horizon: int = 3) -> Dict:
        ref = self.ctx.now(now)
        agg = self._aggregate_series(domain, ref)
        projections = [forecast(agg, h) for h in range(1, horizon + 1)]
        return {
            "domain": domain,
            "horizon": horizon,
            "current_level": round(sum(agg[-max(1, self.window // 6):]), 4),
            "slope": round(slope(agg), 6),
            "projection": projections,
            "projected_next": projections[0] if projections else 0.0,
        }

    def entity_forecast(self, domain: str, now: Optional[float] = None,
                        horizon: int = 3, limit: int = 15) -> List[Dict]:
        ref = self.ctx.now(now)
        series = self.ctx.bucketed(domain, ref, self.bucket_seconds, self.window)
        rows = []
        for entity in series:
            ys = series[entity]
            rows.append({"entity": entity, "domain": domain,
                         "projected_next": forecast(ys, 1),
                         "projection": [forecast(ys, h) for h in range(1, horizon + 1)],
                         "slope": round(slope(ys), 6)})
        rows.sort(key=lambda d: (-d["projected_next"], -d["slope"], d["entity"]))
        return rows[:limit]

    def report(self, now: Optional[float] = None, horizon: int = 3) -> Dict:
        """Forecast the four required signals (utilization / verification / diversity / plugins)."""
        return {
            "capability_utilization": self.domain_forecast("capability", now, horizon),
            "verification_coverage": self.domain_forecast("verification", now, horizon),
            "source_diversity": self.domain_forecast("source", now, horizon),
            "plugin_adoption": self.domain_forecast("plugin", now, horizon),
            "method": "moving_average + linear_slope (bounded, deterministic, non-stochastic)",
        }
