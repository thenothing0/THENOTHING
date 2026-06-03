"""
PluginHealthStore + PluginHealthAnalyzer (Phase M).

Event-sourced, append-only plugin/capability/adapter usage learning under
`data/plugin_health.db`. Every metric is a pure function of the event log → rebuildable &
deterministic. Idempotent via optional dedup_key (UNIQUE). Single-query aggregation. No
canonical writes; promotion.py / confidence.py untouched.
"""

from __future__ import annotations

import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

_DEFAULT_DB = Path(__file__).resolve().parents[2] / "data" / "plugin_health.db"

EV_PLUGIN = "plugin_usage"
EV_CAPABILITY = "capability_usage"
EV_ADAPTER = "adapter_usage"
EV_SELECTION = "selection"
_EVENT_TYPES = (EV_PLUGIN, EV_CAPABILITY, EV_ADAPTER, EV_SELECTION)


@dataclass
class PluginUsage:
    plugin_id: str
    plugin_usage: int = 0
    capability_usage: int = 0
    adapter_usage: int = 0
    selection_frequency: int = 0
    distinct_capabilities: int = 0
    last_used_at: Optional[float] = None

    @property
    def total_events(self) -> int:
        return self.plugin_usage + self.capability_usage + self.adapter_usage + self.selection_frequency

    def to_dict(self) -> Dict:
        return {"plugin_id": self.plugin_id, "plugin_usage": self.plugin_usage,
                "capability_usage": self.capability_usage, "adapter_usage": self.adapter_usage,
                "selection_frequency": self.selection_frequency,
                "distinct_capabilities": self.distinct_capabilities,
                "total_events": self.total_events, "last_used_at": self.last_used_at}


class PluginHealthStore:
    def __init__(self, db_path: Optional[Path | str] = None):
        self.db_path = Path(db_path) if db_path else Path(
            os.environ.get("HYDRA_PLUGIN_HEALTH_DB") or _DEFAULT_DB)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(str(self.db_path), timeout=30)
        c.row_factory = sqlite3.Row
        return c

    def _init(self) -> None:
        c = self._conn()
        try:
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA synchronous=NORMAL")
            c.executescript("""
                CREATE TABLE IF NOT EXISTS plugin_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    plugin_id TEXT NOT NULL, capability_id TEXT, adapter_id TEXT,
                    event_type TEXT NOT NULL, occurred_at REAL NOT NULL,
                    dedup_key TEXT, UNIQUE(dedup_key)
                );
                CREATE INDEX IF NOT EXISTS idx_pe_plugin ON plugin_events(plugin_id);
            """)
            c.commit()
        finally:
            c.close()

    def record(self, plugin_id: str, event_type: str, capability_id: str = "",
               adapter_id: str = "", dedup_key: Optional[str] = None) -> bool:
        if not plugin_id:
            raise ValueError("plugin_id is required")
        if event_type not in _EVENT_TYPES:
            raise ValueError(f"event_type must be one of {_EVENT_TYPES}, got {event_type!r}")
        c = self._conn()
        try:
            cur = c.execute(
                "INSERT OR IGNORE INTO plugin_events (plugin_id, capability_id, adapter_id, "
                "event_type, occurred_at, dedup_key) VALUES (?,?,?,?,?,?)",
                (plugin_id, capability_id, adapter_id, event_type, time.time(), dedup_key))
            c.commit()
            return cur.rowcount == 1
        finally:
            c.close()

    def all_usage(self) -> List[PluginUsage]:
        c = self._conn()
        try:
            rows = c.execute(
                "SELECT plugin_id, "
                "SUM(event_type='plugin_usage') pu, SUM(event_type='capability_usage') cu, "
                "SUM(event_type='adapter_usage') au, SUM(event_type='selection') sf, "
                "COUNT(DISTINCT CASE WHEN capability_id != '' THEN capability_id END) dc, "
                "MAX(occurred_at) last FROM plugin_events GROUP BY plugin_id").fetchall()
        finally:
            c.close()
        out = [PluginUsage(plugin_id=r["plugin_id"], plugin_usage=int(r["pu"] or 0),
                           capability_usage=int(r["cu"] or 0), adapter_usage=int(r["au"] or 0),
                           selection_frequency=int(r["sf"] or 0),
                           distinct_capabilities=int(r["dc"] or 0), last_used_at=r["last"])
               for r in rows]
        out.sort(key=lambda u: u.plugin_id)
        return out

    def usage(self, plugin_id: str) -> PluginUsage:
        for u in self.all_usage():
            if u.plugin_id == plugin_id:
                return u
        return PluginUsage(plugin_id=plugin_id)

    def reset(self) -> None:
        c = self._conn()
        try:
            c.execute("DELETE FROM plugin_events")
            c.commit()
        finally:
            c.close()


class PluginHealthAnalyzer:
    """Derived plugin metrics: combines usage events with the registry's declared counts."""

    def __init__(self, registry=None, store: Optional[PluginHealthStore] = None):
        from hydra.plugins.plugin_registry import PluginRegistry
        self.registry = registry or PluginRegistry()
        self.store = store or PluginHealthStore()

    def _declared(self) -> Dict[str, int]:
        return {pd.plugin_id: len(pd.capabilities) for pd in self.registry.enabled_plugins()}

    def report(self) -> List[Dict]:
        declared = self._declared()
        usage = {u.plugin_id: u for u in self.store.all_usage()}
        out = []
        for pid in sorted(declared):
            u = usage.get(pid, PluginUsage(plugin_id=pid))
            decl = max(1, declared[pid])
            adoption = round(min(1.0, u.distinct_capabilities / decl), 4)
            diversity = round(min(1.0, u.distinct_capabilities / decl), 4)
            effectiveness = round(u.selection_frequency / u.capability_usage, 4) \
                if u.capability_usage else 0.0
            health = round(0.5 * adoption + 0.3 * min(1.0, effectiveness) + 0.2 * diversity, 4)
            out.append({**u.to_dict(), "declared_capabilities": declared[pid],
                        "plugin_adoption": adoption, "plugin_diversity": diversity,
                        "plugin_effectiveness": effectiveness, "plugin_health": health})
        out.sort(key=lambda d: (-d["plugin_health"], d["plugin_id"]))
        return out
