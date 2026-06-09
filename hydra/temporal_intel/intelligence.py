"""
TemporalIntelligence (Phase O) — the unified temporal read surface.

Composes the trend / momentum / forecast / decay / anomaly analyzers over ONE shared
TemporalContext (load-once, O(E)) and exposes the high-level views the MCP layer serves:
temporal_summary, strongest/weakest trends, emerging/declining capabilities, growth/decay
forecasts, anomaly report, and an overall temporal-health score. Read-only, deterministic,
advisory.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from hydra.temporal_intel.advisor import TemporalAdvisor
from hydra.temporal_intel.anomaly import TemporalAnomalyDetector
from hydra.temporal_intel.context import TemporalContext
from hydra.temporal_intel.decay import DecayAnalyzer
from hydra.temporal_intel.forecast import TemporalForecastEngine
from hydra.temporal_intel.trends import TREND_DOMAINS, MomentumAnalyzer, TrendAnalyzer


class TemporalIntelligence:
    def __init__(self, context: Optional[TemporalContext] = None):
        self.ctx = (context or TemporalContext()).load()
        self.trend = TrendAnalyzer(self.ctx)
        self.momentum = MomentumAnalyzer(self.ctx)
        self.forecaster = TemporalForecastEngine(self.ctx)
        self.decay = DecayAnalyzer(self.ctx)
        self.anomaly = TemporalAnomalyDetector(self.ctx)
        self.advisor = TemporalAdvisor(self.ctx)

    # ── individual views ─────────────────────────────────────────────────────────
    def strongest_trends(self, now: Optional[float] = None, limit: int = 10) -> List[Dict]:
        rows: List[Dict] = []
        for d in TREND_DOMAINS:
            rows.extend(self.trend.domain_trends(d, now))
        rows.sort(key=lambda d: (-d["slope"], -d["total_activity"], d["domain"], d["entity"]))
        return rows[:limit]

    def weakest_trends(self, now: Optional[float] = None, limit: int = 10) -> List[Dict]:
        rows: List[Dict] = []
        for d in TREND_DOMAINS:
            rows.extend(self.trend.domain_trends(d, now))
        rows.sort(key=lambda d: (d["slope"], -d["total_activity"], d["domain"], d["entity"]))
        return rows[:limit]

    def emerging_capabilities(self, now: Optional[float] = None) -> List[Dict]:
        return self.trend.emerging("capability", now)

    def declining_capabilities(self, now: Optional[float] = None) -> List[Dict]:
        return self.trend.declining_entities("capability", now)

    def growth_forecast(self, now: Optional[float] = None) -> Dict:
        return self.forecaster.report(now)

    def decay_forecast(self, now: Optional[float] = None) -> Dict:
        return self.decay.report(now)

    def anomaly_report(self, now: Optional[float] = None) -> Dict:
        return self.anomaly.report(now)

    # ── health & summary ─────────────────────────────────────────────────────────
    def temporal_health(self, now: Optional[float] = None) -> Dict:
        """0-100 temporal-health score: rewards rising/active knowledge, penalizes decay &
        anomalies. Advisory; never alters confidence/promotion."""
        ref = self.ctx.now(now)
        strongest = self.strongest_trends(now)
        rising = sum(1 for t in strongest if t["direction"] == "rising")
        declining = sum(1 for t in strongest if t["direction"] == "declining")
        decay = self.decay.report(now)
        anomalies = self.anomaly.report(now)
        total_events = self.ctx.total_events()

        if total_events == 0:
            return {"temporal_health_score": None, "status": "no_temporal_data",
                    "total_events": 0, "reference_time": ref, "advisory": True}

        high_decay = decay["by_severity"].get("high", 0)
        # Deterministic 0-100 blend (bounded components).
        base = 60.0
        trend_term = 8.0 * (rising - declining)
        decay_term = -5.0 * high_decay
        anomaly_term = -2.0 * anomalies["count"]
        score = max(0.0, min(100.0, base + trend_term + decay_term + anomaly_term))
        return {
            "temporal_health_score": round(score, 2),
            "status": "healthy" if score >= 60 else ("watch" if score >= 40 else "degrading"),
            "rising_trends": rising, "declining_trends": declining,
            "high_severity_decay": high_decay, "anomaly_count": anomalies["count"],
            "total_events": total_events, "reference_time": ref, "advisory": True,
        }

    def temporal_summary(self, now: Optional[float] = None) -> Dict:
        # Compute each derived report ONCE; the shared context memoizes bucketing so the
        # whole summary stays O(E) regardless of how many views read the same domains.
        decay = self.decay.report(now)
        anomalies = self.anomaly_report(now)
        return {
            "temporal_health": self.temporal_health(now),
            "strongest_trends": self.strongest_trends(now, limit=5),
            "weakest_trends": self.weakest_trends(now, limit=5),
            "emerging_capabilities": self.emerging_capabilities(now)[:5],
            "declining_capabilities": self.declining_capabilities(now)[:5],
            "decay": {"count": decay["count"], "by_severity": decay["by_severity"]},
            "anomalies": {"count": anomalies["count"], "by_type": anomalies["by_type"]},
            "recommendations": self.advisor.recommendations(now, limit=5),
            "domains_tracked": self.ctx.domains(),
            "total_events": self.ctx.total_events(),
            "advisory": True,
        }
