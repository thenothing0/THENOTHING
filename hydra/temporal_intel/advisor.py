"""
TemporalAdvisor (Phase O).

Turns temporal signals into bounded, advisory recommendations (diversify verification, exercise
underused adapters, grow coverage in declining areas, …). It NEVER mutates state, never triggers
actions, never confirms or promotes anything. Pure, deterministic, read-only.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from hydra.temporal_intel.context import TemporalContext
from hydra.temporal_intel.decay import DecayAnalyzer
from hydra.temporal_intel.trends import TrendAnalyzer


class TemporalAdvisor:
    def __init__(self, context: Optional[TemporalContext] = None):
        self.ctx = (context or TemporalContext()).load()
        self.trends = TrendAnalyzer(self.ctx)
        self.decay = DecayAnalyzer(self.ctx)

    def recommendations(self, now: Optional[float] = None, limit: int = 10) -> List[Dict]:
        recs: List[Dict] = []

        # 1) high-severity decay → review/re-exercise
        for f in self.decay.domain_decay("capability", now):
            if f.severity == "high":
                recs.append({"priority": 1, "kind": "decay",
                             "recommendation": f"exercise or retire stale capability '{f.entity}'",
                             "rationale": f.rationale})

        # 2) declining verification methods → diversify verification
        for t in self.trends.declining("verification", now)[:3]:
            recs.append({"priority": 2, "kind": "verification",
                         "recommendation": f"diversify verification — method '{t['entity']}' is declining",
                         "rationale": f"slope {t['slope']}, momentum {t['momentum']}"})

        # 3) declining source activity → improve source diversity
        for t in self.trends.declining("source", now)[:3]:
            recs.append({"priority": 2, "kind": "source",
                         "recommendation": f"improve source diversity — '{t['entity']}' activity is falling",
                         "rationale": f"slope {t['slope']}"})

        # 4) stale adapters → exercise underutilized adapters
        for f in self.decay.domain_decay("adapter", now)[:3]:
            recs.append({"priority": 3, "kind": "adapter",
                         "recommendation": f"exercise underutilized adapter '{f.entity}'",
                         "rationale": f.rationale})

        recs.sort(key=lambda r: (r["priority"], r["kind"], r["recommendation"]))
        return recs[:limit]
