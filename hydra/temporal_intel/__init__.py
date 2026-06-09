"""
Hydra Temporal Intelligence Layer — Phase O.

A fully derived, deterministic, offline-first layer that understands how Hydra's knowledge
evolves over time: trends, momentum, decay, emerging/declining areas, bounded forecasts, and
temporal anomalies. Built ENTIRELY from the existing derived event logs (source/verification/
tool-health/plugin-health/decision/federation); it never reads or writes the canonical wiki and
never touches promotion.py / confidence.py. Advisory only.

This is a NEW package (`hydra.temporal_intel`) — it does not reuse or modify the legacy
`hydra.temporal` infrastructure-history subsystem.
"""

from .advisor import TemporalAdvisor
from .anomaly import TemporalAnomalyDetector
from .context import TemporalContext, TemporalEvent
from .decay import DecayAnalyzer, TemporalDecayFinding
from .forecast import TemporalForecastEngine
from .intelligence import TemporalIntelligence
from .store import TemporalStore
from .trends import MomentumAnalyzer, TrendAnalyzer

__all__ = [
    "TemporalStore",
    "TemporalContext",
    "TemporalEvent",
    "TrendAnalyzer",
    "MomentumAnalyzer",
    "TemporalForecastEngine",
    "DecayAnalyzer",
    "TemporalDecayFinding",
    "TemporalAnomalyDetector",
    "TemporalIntelligence",
    "TemporalAdvisor",
]
