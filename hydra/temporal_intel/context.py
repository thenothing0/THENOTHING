"""
TemporalContext (Phase O) — load-once aggregation of every derived event log.

Reads the timestamped event tables of the existing learning/runtime/federation stores ONCE
(single query each, read-only) into a flat, sorted list of `TemporalEvent`s, then exposes them
grouped by domain. Every temporal analyzer shares ONE context, so the underlying logs are never
re-scanned → total work is O(E) in the number of events.

Robust offline: any absent DB/table is skipped (cold-start yields empty series, never an error).
Read-only — opens each store's own DB file (honoring its env override) and never writes it.
Touches nothing canonical.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional, Tuple

from hydra.temporal_intel.util import (
    DEFAULT_BUCKET_SECONDS,
    DEFAULT_WINDOW,
    bucket_counts,
)

_DATA = Path(__file__).resolve().parents[2] / "data"

_SUCCESS = {"success", "confirmed", "accepted", "pass"}
_FAILURE = {"failure", "rejected", "timeout", "fail", "error"}


def _success_of(outcome: Optional[str]) -> Optional[bool]:
    if not outcome:
        return None
    o = str(outcome).strip().lower()
    if o in _SUCCESS:
        return True
    if o in _FAILURE:
        return False
    return None


class TemporalEvent(NamedTuple):
    # NamedTuple (not a dataclass) — far cheaper to construct/store in bulk at 10^6 events.
    domain: str            # source | verification | adapter | capability | plugin | decision | federation | agent
    entity: str
    category: str
    occurred_at: float
    weight: float = 1.0
    success: Optional[bool] = None


# Per-source mapping: (domain, env_var, default_file, table, ts, entity, category, outcome, value).
# Empty string ⇒ column not present. health_events feeds TWO domains (adapter + capability).
_SOURCES = [
    ("source", "HYDRA_SOURCE_LEARNING_DB", "source_learning.db",
     "source_events", "occurred_at", "source_id", "event_type", "", "value"),
    ("verification", "HYDRA_VERIFICATION_DB", "verification_learning.db",
     "verification_events", "occurred_at", "method", "vuln_class", "outcome", ""),
    ("adapter", "HYDRA_TOOL_HEALTH_DB", "tool_health.db",
     "health_events", "occurred_at", "adapter_id", "category", "outcome", ""),
    ("capability", "HYDRA_TOOL_HEALTH_DB", "tool_health.db",
     "health_events", "occurred_at", "capability_id", "category", "outcome", ""),
    ("plugin", "HYDRA_PLUGIN_HEALTH_DB", "plugin_health.db",
     "plugin_events", "occurred_at", "plugin_id", "capability_id", "", ""),
    ("decision", "HYDRA_DECISION_DB", "decision_learning.db",
     "prediction_events", "occurred_at", "subject_key", "metric", "", ""),
    ("federation", "HYDRA_FEDERATION_DB", "federation.db",
     "federation_events", "occurred_at", "peer_id", "event_type", "", ""),
]


class TemporalContext:
    def __init__(self):
        self._by_domain: Dict[str, List[TemporalEvent]] = {}
        self._loaded = False
        self._agent_built = False
        # Memoized derived views — every analyzer shares one context, so each domain is
        # bucketed (and last-seen scanned) at most once per (now, bucket, window).
        self._bucket_cache: Dict[Tuple, Dict[str, List[float]]] = {}
        self._last_seen_cache: Dict[str, Dict[str, float]] = {}

    # ── load (O(E), single pass per store) ──────────────────────────────────────
    def _db_path(self, env_var: str, default_file: str) -> Path:
        return Path(os.environ.get(env_var) or (_DATA / default_file))

    def _read_table(self, key: Tuple[str, str, str], specs: List[Tuple]) -> None:
        """Scan one physical (env, file, table) ONCE and fan its rows out to every domain that
        sources from it (e.g. health_events → adapter + capability). Positional tuple rows (no
        Row factory) keep the per-row cost low at 10^6 events; absent DB/table → skipped."""
        env, fname, table = key
        path = self._db_path(env, fname)
        if not path.exists():
            return
        # Distinct columns needed across all specs for this table (ts first).
        ts_col = specs[0][4]
        cols: List[str] = [ts_col]
        for sp in specs:
            for col in (sp[5], sp[6], sp[7], sp[8]):   # entity, category, outcome, value
                if col and col not in cols:
                    cols.append(col)
        idx = {c: i for i, c in enumerate(cols)}
        try:
            con = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=30)
            try:
                rows = con.execute(f"SELECT {','.join(cols)} FROM {table}").fetchall()
            finally:
                con.close()
        except sqlite3.Error:
            return
        ti = idx[ts_col]
        # Per-spec extraction plan (column positions resolved once, outside the row loop).
        plan = [(sp[0], idx[sp[5]], idx.get(sp[6]) if sp[6] else None,
                 idx.get(sp[7]) if sp[7] else None, idx.get(sp[8]) if sp[8] else None)
                for sp in specs]
        bd = self._by_domain
        sof = _success_of
        for r in rows:
            ts_v = r[ti]
            if ts_v is None:
                continue
            ts_f = float(ts_v)
            for domain, ei, ci, oi, vi in plan:
                ent = r[ei]
                if ent is None:
                    continue
                weight = 1.0
                if vi is not None and r[vi] is not None:
                    try:
                        weight = float(r[vi])
                    except (TypeError, ValueError):
                        weight = 1.0
                    if weight <= 0:
                        weight = 1.0
                cat = r[ci] if ci is not None else ""
                succ = sof(r[oi]) if oi is not None else None
                bd.setdefault(domain, []).append(
                    TemporalEvent(domain, str(ent), str(cat or ""), ts_f, weight, succ))

    def load(self) -> "TemporalContext":
        if self._loaded:
            return self
        # No global sort: every downstream aggregation (bucket counts, last-seen max) is
        # order-independent and all outputs are sorted — so insertion order is fine and we
        # avoid an O(E log E) pass on millions of events. Each physical table is scanned once.
        groups: Dict[Tuple[str, str, str], List[Tuple]] = {}
        for spec in _SOURCES:
            groups.setdefault((spec[1], spec[2], spec[3]), []).append(spec)
        for key, specs in groups.items():
            self._read_table(key, specs)
        self._loaded = True
        return self

    def _ensure_agent_domain(self) -> None:
        """Lazily remap capability activity onto the owning agent (deterministic ownership
        map). Built once, only when the agent domain is actually queried."""
        if self._agent_built:
            return
        self._agent_built = True
        cap_events = self._by_domain.get("capability")
        if not cap_events:
            return
        try:
            from hydra.plugins.ownership import AgentOwnershipResolver
            from hydra.plugins.plugin_catalog import EffectiveCapabilityCatalog
            res = AgentOwnershipResolver(EffectiveCapabilityCatalog().load()).resolve()
            owner = {a["capability_id"]: a["owner"] for a in res.get("assignments", [])
                     if a.get("owner")}
        except Exception:
            return
        agent_events = [TemporalEvent("agent", owner[e.entity], e.category, e.occurred_at,
                                      e.weight, e.success)
                        for e in cap_events if e.entity in owner]
        if agent_events:
            self._by_domain["agent"] = agent_events

    # ── access ──────────────────────────────────────────────────────────────────
    def now(self, injected: Optional[float] = None) -> float:
        """Deterministic reference time: injected value, else the newest event ts, else 0.0.
        The derived 'agent' domain is skipped (it reuses capability timestamps)."""
        if injected is not None:
            return float(injected)
        self.load()
        return max((e.occurred_at for d, evs in self._by_domain.items() if d != "agent"
                    for e in evs), default=0.0)

    def events(self, domain: str = "") -> List[TemporalEvent]:
        self.load()
        if domain == "agent":
            self._ensure_agent_domain()
        if domain:
            return self._by_domain.get(domain, [])
        return [e for evs in self._by_domain.values() for e in evs]

    def domains(self) -> List[str]:
        self.load()
        self._ensure_agent_domain()
        return sorted(self._by_domain)

    def entities(self, domain: str) -> List[str]:
        return sorted({e.entity for e in self.events(domain)})

    def bucketed(self, domain: str, now: float,
                 bucket_seconds: float = DEFAULT_BUCKET_SECONDS,
                 window: int = DEFAULT_WINDOW) -> Dict[str, List[float]]:
        """Per-entity per-bucket counts for a domain, MEMOIZED by (domain, now, bucket, window).
        The first analyzer to ask pays O(events_in_domain); the rest reuse the cache."""
        key = (domain, round(float(now), 6), bucket_seconds, window)
        cached = self._bucket_cache.get(key)
        if cached is None:
            cached = bucket_counts(self.events(domain), now, bucket_seconds, window)
            self._bucket_cache[key] = cached
        return cached

    def last_seen(self, domain: str) -> Dict[str, float]:
        cached = self._last_seen_cache.get(domain)
        if cached is None:
            cached = {}
            for e in self.events(domain):
                if e.occurred_at > cached.get(e.entity, -1.0):
                    cached[e.entity] = e.occurred_at
            self._last_seen_cache[domain] = cached
        return cached

    def total_events(self) -> int:
        """Underlying events ingested (the derived 'agent' domain is not double-counted)."""
        self.load()
        return sum(len(evs) for d, evs in self._by_domain.items() if d != "agent")
