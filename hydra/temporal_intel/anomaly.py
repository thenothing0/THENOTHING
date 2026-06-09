"""
TemporalAnomalyDetector (Phase O).

Flags deterministic, advisory temporal anomalies in the bucket series:
  * spike       — a bucket far above the entity's mean (> ANOMALY_SIGMA stdevs)
  * drop        — a bucket far below the mean
  * inactivity  — a run of trailing empty buckets after prior activity
  * concentration — a single entity holding a dominant share of a domain's activity

No alerts, no side effects — findings only. Deterministic (fixed thresholds). O(E).
"""

from __future__ import annotations

from typing import Dict, List, Optional

from hydra.temporal_intel.context import TemporalContext
from hydra.temporal_intel.util import (
    ANOMALY_SIGMA,
    CONCENTRATION_SHARE,
    DEFAULT_BUCKET_SECONDS,
    DEFAULT_WINDOW,
    INACTIVITY_BUCKETS,
    mean,
    pstdev,
)

ANOMALY_DOMAINS = ("capability", "adapter", "plugin", "verification", "source")


class TemporalAnomalyDetector:
    def __init__(self, context: Optional[TemporalContext] = None,
                 bucket_seconds: float = DEFAULT_BUCKET_SECONDS, window: int = DEFAULT_WINDOW):
        self.ctx = (context or TemporalContext()).load()
        self.bucket_seconds = bucket_seconds
        self.window = window

    def _entity_anomalies(self, domain: str, entity: str, ys: List[float]) -> List[Dict]:
        out: List[Dict] = []
        mu, sd = mean(ys), pstdev(ys)
        if sd > 0:
            for i, y in enumerate(ys):
                if y > mu + ANOMALY_SIGMA * sd:
                    out.append({"entity": entity, "domain": domain, "type": "spike",
                                "bucket": i, "value": round(y, 4), "mean": round(mu, 4),
                                "rationale": f"bucket {i} value {round(y,4)} > mean+{ANOMALY_SIGMA}σ"})
                elif mu > 0 and y < mu - ANOMALY_SIGMA * sd:
                    out.append({"entity": entity, "domain": domain, "type": "drop",
                                "bucket": i, "value": round(y, 4), "mean": round(mu, 4),
                                "rationale": f"bucket {i} value {round(y,4)} < mean-{ANOMALY_SIGMA}σ"})
        # trailing inactivity after prior activity
        if any(y > 0 for y in ys):
            trailing = 0
            for y in reversed(ys):
                if y > 0:
                    break
                trailing += 1
            if trailing >= INACTIVITY_BUCKETS:
                out.append({"entity": entity, "domain": domain, "type": "inactivity",
                            "bucket": self.window - trailing, "value": 0.0,
                            "mean": round(mu, 4),
                            "rationale": f"{trailing} trailing empty buckets after prior activity"})
        return out

    def domain_anomalies(self, domain: str, now: Optional[float] = None) -> List[Dict]:
        ref = self.ctx.now(now)
        series = self.ctx.bucketed(domain, ref, self.bucket_seconds, self.window)
        out: List[Dict] = []
        for entity in sorted(series):
            out.extend(self._entity_anomalies(domain, entity, series[entity]))
        # concentration: one entity dominating the domain's total activity
        totals = {ent: sum(ys) for ent, ys in series.items()}
        grand = sum(totals.values())
        if grand > 0:
            for ent in sorted(totals):
                share = totals[ent] / grand
                if share > CONCENTRATION_SHARE and len(totals) > 1:
                    out.append({"entity": ent, "domain": domain, "type": "concentration",
                                "bucket": -1, "value": round(share, 4), "mean": 0.0,
                                "rationale": f"'{ent}' holds {round(share*100,1)}% of {domain} activity"})
        out.sort(key=lambda d: (d["type"], d["entity"], d["bucket"]))
        return out

    def report(self, now: Optional[float] = None) -> Dict:
        anomalies: List[Dict] = []
        for d in ANOMALY_DOMAINS:
            anomalies.extend(self.domain_anomalies(d, now))
        by_type: Dict[str, int] = {}
        for a in anomalies:
            by_type[a["type"]] = by_type.get(a["type"], 0) + 1
        return {"anomalies": anomalies, "count": len(anomalies),
                "by_type": dict(sorted(by_type.items())), "advisory": True}
