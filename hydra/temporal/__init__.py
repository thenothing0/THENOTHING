"""
╔══════════════════════════════════════════════════════════════╗
║  Temporal Intelligence Engine                                ║
║  DNS history, infrastructure evolution, historical endpoint  ║
║  recovery, forgotten asset detection, exposure timelines     ║
╚══════════════════════════════════════════════════════════════╝
"""

import logging
import time
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger("hydra.temporal")


@dataclass
class TemporalRecord:
    """A point-in-time record for an asset."""
    asset: str
    record_type: str              # dns, ip, technology, endpoint, certificate
    value: str
    first_seen: float = 0.0
    last_seen: float = 0.0
    source: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class InfrastructureChange:
    """A detected infrastructure change."""
    asset: str
    change_type: str              # dns_change, ip_change, tech_change, cert_change
    old_value: str = ""
    new_value: str = ""
    detected_at: float = field(default_factory=time.time)
    significance: str = "low"     # low, medium, high, critical
    reasoning: str = ""


@dataclass
class ForgottenAsset:
    """A potentially forgotten/legacy asset."""
    asset: str
    asset_type: str
    last_seen: float = 0.0
    age_days: float = 0.0
    risk_indicators: List[str] = field(default_factory=list)
    confidence: float = 0.3
    reasoning: str = ""


class TemporalIntelligenceEngine:
    """
    Time-aware attack intelligence engine.

    Reasons about:
      - How infrastructure changed over time
      - What legacy assets may still exist
      - What systems were forgotten
      - DNS history → old IPs → direct access bypass
      - Certificate transparency → historical subdomains
      - Wayback Machine → old endpoints with vulns
      - Cloud migrations → leftover resources
    """

    def __init__(self):
        self._records: Dict[str, List[TemporalRecord]] = {}
        self._changes: List[InfrastructureChange] = []
        self._forgotten: List[ForgottenAsset] = []

    def add_record(self, record: TemporalRecord):
        """Add a temporal record for an asset."""
        self._records.setdefault(record.asset, []).append(record)

    def add_dns_history(self, domain: str,
                        history: List[Dict[str, Any]]):
        """Add DNS history records."""
        for entry in history:
            self.add_record(TemporalRecord(
                asset=domain,
                record_type="dns",
                value=entry.get("ip", entry.get("value", "")),
                first_seen=entry.get("first_seen", 0),
                last_seen=entry.get("last_seen", 0),
                source=entry.get("source", "dns_history"),
                metadata=entry,
            ))

    def detect_changes(self, asset: str) -> List[InfrastructureChange]:
        """Detect infrastructure changes for an asset."""
        records = self._records.get(asset, [])
        if len(records) < 2:
            return []

        changes = []
        # Sort by first_seen
        sorted_records = sorted(records, key=lambda r: r.first_seen)

        # Group by record_type
        by_type: Dict[str, List[TemporalRecord]] = {}
        for r in sorted_records:
            by_type.setdefault(r.record_type, []).append(r)

        for rtype, type_records in by_type.items():
            for i in range(1, len(type_records)):
                old = type_records[i - 1]
                new = type_records[i]
                if old.value != new.value:
                    significance = self._assess_change_significance(
                        rtype, old.value, new.value)
                    change = InfrastructureChange(
                        asset=asset,
                        change_type=f"{rtype}_change",
                        old_value=old.value,
                        new_value=new.value,
                        significance=significance,
                        reasoning=self._change_reasoning(rtype, old.value, new.value),
                    )
                    changes.append(change)
                    self._changes.append(change)

        return changes

    def find_forgotten_assets(self,
                               current_assets: List[str],
                               stale_threshold_days: float = 180) -> List[ForgottenAsset]:
        """Find potentially forgotten assets."""
        forgotten = []
        now = time.time()
        threshold = stale_threshold_days * 86400

        for asset, records in self._records.items():
            if asset in current_assets:
                continue  # Still active

            latest = max(r.last_seen for r in records) if records else 0
            if latest > 0 and (now - latest) > threshold:
                age_days = (now - latest) / 86400
                risk_indicators = []

                # Check for concerning patterns
                for r in records:
                    if r.record_type == "dns" and r.value:
                        risk_indicators.append(f"Old DNS: {r.value}")
                    if r.record_type == "technology":
                        risk_indicators.append(f"Old tech: {r.value}")

                forgotten.append(ForgottenAsset(
                    asset=asset,
                    asset_type="domain",
                    last_seen=latest,
                    age_days=round(age_days, 1),
                    risk_indicators=risk_indicators[:5],
                    confidence=min(0.8, 0.3 + age_days / 365),
                    reasoning=f"Not seen for {age_days:.0f} days, may have outdated security",
                ))

        self._forgotten = forgotten
        forgotten.sort(key=lambda f: f.age_days, reverse=True)
        return forgotten

    def find_old_ips(self, domain: str) -> List[Dict[str, Any]]:
        """Find historical IPs for a domain (WAF bypass potential)."""
        records = self._records.get(domain, [])
        ip_records = [r for r in records if r.record_type == "dns" and r.value]

        # Get current IP (most recent)
        current_ip = ""
        if ip_records:
            current_ip = max(ip_records, key=lambda r: r.last_seen).value

        old_ips = []
        for r in ip_records:
            if r.value != current_ip:
                old_ips.append({
                    "ip": r.value,
                    "first_seen": r.first_seen,
                    "last_seen": r.last_seen,
                    "potential": "WAF bypass via direct IP access" if current_ip else "",
                    "risk": "high" if r.value.startswith(("10.", "172.", "192.168.")) else "medium",
                })

        return old_ips

    def generate_exposure_timeline(self, asset: str) -> List[Dict[str, Any]]:
        """Generate a chronological exposure timeline."""
        records = self._records.get(asset, [])
        events = []

        for r in sorted(records, key=lambda r: r.first_seen):
            events.append({
                "timestamp": r.first_seen,
                "event": f"{r.record_type}: {r.value}",
                "source": r.source,
                "type": r.record_type,
            })

        changes = [c for c in self._changes if c.asset == asset]
        for c in changes:
            events.append({
                "timestamp": c.detected_at,
                "event": f"Change: {c.old_value} → {c.new_value}",
                "significance": c.significance,
                "type": "change",
            })

        events.sort(key=lambda e: e["timestamp"])
        return events

    # ── Helpers ───────────────────────────────

    def _assess_change_significance(self, rtype: str,
                                     old: str, new: str) -> str:
        if rtype == "dns":
            # IP change could indicate migration
            if old.startswith(("10.", "172.", "192.168.")) != new.startswith(("10.", "172.", "192.168.")):
                return "high"
            return "medium"
        if rtype == "technology":
            return "medium"
        if rtype == "certificate":
            return "low"
        return "low"

    def _change_reasoning(self, rtype: str, old: str, new: str) -> str:
        if rtype == "dns":
            return f"DNS changed from {old} to {new} — possible migration or CDN change"
        if rtype == "technology":
            return f"Technology changed from {old} to {new} — check for migration issues"
        return f"{rtype} changed from {old} to {new}"

    def get_summary(self) -> Dict[str, Any]:
        return {
            "tracked_assets": len(self._records),
            "total_records": sum(len(r) for r in self._records.values()),
            "detected_changes": len(self._changes),
            "forgotten_assets": len(self._forgotten),
        }
