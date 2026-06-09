"""
OffensiveContext (Phase P) — load-once aggregation over derived logs + static catalogs.

Reads the existing derived learning logs ONCE (read-only) and joins them with the STATIC
declarative catalogs (effective capabilities, dependency graph, adapters, agent ownership,
skills) to expose offensive rollups indexed by capability / adapter / vuln-class. Every
analyzer shares ONE context, so the underlying logs are never re-scanned → O(E).

Robust offline: any absent DB/table is skipped (cold-start yields the catalog priors only,
never an error). Read-only — opens each store's own DB (honoring its env override) and never
writes it. Touches nothing canonical (wiki / promotion.py / confidence.py).
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Dict, List, Optional, Tuple

_DATA = Path(__file__).resolve().parents[2] / "data"
_SKILLS_DIR = Path(__file__).resolve().parents[2] / "skills"

_SUCCESS = {"success", "confirmed", "accepted", "pass", "verified", "valid"}
_FAILURE = {"failure", "rejected", "timeout", "fail", "error", "invalid"}


def _success_of(outcome) -> Optional[bool]:
    if outcome is None:
        return None
    o = str(outcome).strip().lower()
    if o in _SUCCESS:
        return True
    if o in _FAILURE:
        return False
    return None


class Outcome:
    """Cheap mutable per-entity rollup (there can be many entities)."""

    __slots__ = ("events", "successes", "failures", "last_seen")

    def __init__(self):
        self.events = 0
        self.successes = 0
        self.failures = 0
        self.last_seen = 0.0

    def add(self, success: Optional[bool], ts: float) -> None:
        self.events += 1
        if success is True:
            self.successes += 1
        elif success is False:
            self.failures += 1
        if ts and ts > self.last_seen:
            self.last_seen = ts

    @property
    def decided(self) -> int:
        return self.successes + self.failures

    @property
    def success_rate(self) -> Optional[float]:
        return round(self.successes / self.decided, 4) if self.decided else None

    def to_dict(self) -> Dict:
        return {"events": self.events, "successes": self.successes,
                "failures": self.failures, "decided": self.decided,
                "success_rate": self.success_rate}


def _load_skills() -> List[Dict]:
    """Declarative skill bridge data from skills/<slug>/SKILL.yaml (deterministic, defensive)."""
    if not _SKILLS_DIR.exists():
        return []
    try:
        import yaml
    except Exception:  # pragma: no cover - pyyaml always present in this repo
        return []
    out: List[Dict] = []
    for p in sorted(_SKILLS_DIR.glob("*/SKILL.yaml")):
        try:
            d = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        except Exception:
            continue
        if not isinstance(d, dict):
            continue
        out.append({
            "skill_id": str(d.get("id") or p.parent.name),
            "name": str(d.get("name") or p.parent.name),
            "category": str(d.get("category") or p.parent.name),
            "slug": p.parent.name,
            "mcp_tools": sorted(str(x) for x in (d.get("mcp_tools") or [])),
            "chain_to": sorted(str(x) for x in (d.get("chain_to") or [])),
        })
    out.sort(key=lambda s: s["skill_id"])
    return out


class OffensiveContext:
    def __init__(self, catalog=None, graph=None, adapters=None, registry=None):
        self._loaded = False
        self._registry = registry
        self._catalog = catalog
        self._graph = graph
        self._adapters = adapters
        self._ownership: Optional[Dict] = None
        self._owner_of: Optional[Dict[str, Optional[str]]] = None
        self._skills: Optional[List[Dict]] = None
        self.cap_outcomes: Dict[str, Outcome] = {}
        self.adapter_outcomes: Dict[str, Outcome] = {}
        self.vuln_class: Dict[str, Outcome] = {}
        self.method_outcomes: Dict[str, Outcome] = {}
        self._max_ts = 0.0
        self._total_events = 0

    # ── derived-log loading (O(E), single scan per physical table) ────────────────
    def _db(self, env: str, fname: str) -> Path:
        return Path(os.environ.get(env) or (_DATA / fname))

    def _scan(self, env: str, fname: str, table: str,
              cols: List[str]) -> Tuple[Dict[str, int], List]:
        path = self._db(env, fname)
        if not path.exists():
            return {}, []
        try:
            con = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=30)
            try:
                have = {r[1] for r in con.execute(f"PRAGMA table_info({table})").fetchall()}
                use = [c for c in cols if c in have]
                if "occurred_at" not in use or len(use) < 2:
                    return {}, []
                rows = con.execute(f"SELECT {','.join(use)} FROM {table}").fetchall()
            finally:
                con.close()
        except sqlite3.Error:
            return {}, []
        return {c: i for i, c in enumerate(use)}, rows

    def load(self) -> "OffensiveContext":
        if self._loaded:
            return self
        # tool_health.health_events → capability AND adapter exercise/outcome (one scan)
        idx, rows = self._scan(
            "HYDRA_TOOL_HEALTH_DB", "tool_health.db", "health_events",
            ["occurred_at", "capability_id", "adapter_id", "category", "outcome"])
        if rows:
            ti, ci = idx.get("occurred_at"), idx.get("capability_id")
            ai, oi = idx.get("adapter_id"), idx.get("outcome")
            for r in rows:
                ts = float(r[ti]) if ti is not None and r[ti] is not None else 0.0
                succ = _success_of(r[oi]) if oi is not None else None
                self._total_events += 1
                if ts > self._max_ts:
                    self._max_ts = ts
                if ci is not None and r[ci] is not None:
                    self.cap_outcomes.setdefault(str(r[ci]), Outcome()).add(succ, ts)
                if ai is not None and r[ai] is not None:
                    self.adapter_outcomes.setdefault(str(r[ai]), Outcome()).add(succ, ts)
        # verification_learning.verification_events → per vuln_class AND per method
        idx, rows = self._scan(
            "HYDRA_VERIFICATION_DB", "verification_learning.db", "verification_events",
            ["occurred_at", "method", "vuln_class", "outcome"])
        if rows:
            ti, mi = idx.get("occurred_at"), idx.get("method")
            vi, oi = idx.get("vuln_class"), idx.get("outcome")
            for r in rows:
                ts = float(r[ti]) if ti is not None and r[ti] is not None else 0.0
                succ = _success_of(r[oi]) if oi is not None else None
                self._total_events += 1
                if ts > self._max_ts:
                    self._max_ts = ts
                if vi is not None and r[vi] is not None:
                    self.vuln_class.setdefault(str(r[vi]), Outcome()).add(succ, ts)
                if mi is not None and r[mi] is not None:
                    self.method_outcomes.setdefault(str(r[mi]), Outcome()).add(succ, ts)
        self._loaded = True
        return self

    # ── static catalogs (lazy, shared across analyzers, injectable for tests) ─────
    def catalog(self):
        if self._catalog is None:
            from hydra.plugins.plugin_catalog import EffectiveCapabilityCatalog
            self._catalog = EffectiveCapabilityCatalog(self._registry).load()
        return self._catalog

    def graph(self):
        if self._graph is None:
            from hydra.capabilities.dependency_graph import CapabilityDependencyGraph
            edges: List[Dict] = []
            try:
                from hydra.plugins.plugin_registry import PluginRegistry
                reg = self._registry or PluginRegistry()
                edges = reg.plugin_dependency_edges()
            except Exception:
                edges = []
            self._graph = CapabilityDependencyGraph(
                catalog=self.catalog(), plugin_edges=edges).load()
        return self._graph

    def adapters(self):
        if self._adapters is None:
            from hydra.adapters.adapter_registry import AdapterRegistry
            self._adapters = AdapterRegistry(catalog=self.catalog()).load()
        return self._adapters

    def ownership(self) -> Dict:
        if self._ownership is None:
            try:
                from hydra.plugins.ownership import AgentOwnershipResolver
                self._ownership = AgentOwnershipResolver(self.catalog()).resolve()
            except Exception:
                self._ownership = {"assignments": []}
        return self._ownership

    def owner_of(self) -> Dict[str, Optional[str]]:
        if self._owner_of is None:
            self._owner_of = {a["capability_id"]: a.get("owner")
                              for a in self.ownership().get("assignments", [])}
        return self._owner_of

    def skills(self) -> List[Dict]:
        if self._skills is None:
            self._skills = _load_skills()
        return self._skills

    # ── access ────────────────────────────────────────────────────────────────────
    def now(self, injected: Optional[float] = None) -> float:
        """Deterministic reference time: injected value, else the newest event ts, else 0.0."""
        if injected is not None:
            return float(injected)
        self.load()
        return self._max_ts

    def capability_outcome(self, capability_id: str) -> Optional[Outcome]:
        self.load()
        return self.cap_outcomes.get(capability_id)

    def adapter_outcome(self, adapter_id: str) -> Optional[Outcome]:
        self.load()
        return self.adapter_outcomes.get(adapter_id)

    def verification_for(self, finding_types) -> Tuple[Optional[float], int]:
        """(success_rate, attempts) over the vuln_classes matching a capability's finding types;
        (None, 0) when there is no verification evidence."""
        self.load()
        succ = att = 0
        for ft in finding_types:
            o = self.vuln_class.get(ft)
            if o:
                succ += o.successes
                att += o.decided
        if att == 0:
            return None, 0
        return succ / att, att

    def total_events(self) -> int:
        self.load()
        return self._total_events
