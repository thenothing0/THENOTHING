"""
KnowledgeDigestGenerator + digest dataclasses (Phase N).

Turns the LOCAL learning/catalog stores into exchangeable, anonymized digests. A digest
carries AGGREGATE METADATA ONLY — capability ids and abstract category/method labels plus
derived scores. It NEVER carries wiki pages, evidence, findings, targets, raw source ids,
secrets, or exploit payloads (enforced by `assert_safe`).

Four digest kinds:
  * CapabilityDigest   — capability id, category, exercise count, verification coverage, effectiveness
  * SourceDigest       — source CATEGORY (never source id), effectiveness, trust, diversity
  * VerificationDigest — method / evidence-class success rates + verification effectiveness
  * PluginDigest       — plugin capability/adapter counts + ecosystem coverage

`generate()` bundles them into a deterministic envelope (sorted, injected `now`) so two runs
over identical stores produce byte-identical digests (rebuild-identical). Read-only over every
source store; touches nothing canonical.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from hydra.federation.safety import DIGEST_SCHEMA_VERSION, assert_safe, deterministic_id


@dataclass
class CapabilityDigest:
    capability_id: str
    category: str = "reconnaissance"
    exercise_count: int = 0
    verification_coverage: int = 0
    effectiveness: float = 0.0

    def to_dict(self) -> Dict:
        return {"capability_id": self.capability_id, "category": self.category,
                "exercise_count": self.exercise_count,
                "verification_coverage": self.verification_coverage,
                "effectiveness": self.effectiveness}

    @classmethod
    def from_dict(cls, d: Dict) -> "CapabilityDigest":
        return cls(capability_id=str(d.get("capability_id", "")),
                   category=str(d.get("category", "reconnaissance")),
                   exercise_count=int(d.get("exercise_count", 0) or 0),
                   verification_coverage=int(d.get("verification_coverage", 0) or 0),
                   effectiveness=float(d.get("effectiveness", 0.0) or 0.0))


@dataclass
class SourceDigest:
    source_category: str
    effectiveness: float = 0.0
    trust: float = 0.0
    novelty: float = 0.0
    distinct_sources: int = 0

    def to_dict(self) -> Dict:
        return {"source_category": self.source_category, "effectiveness": self.effectiveness,
                "trust": self.trust, "novelty": self.novelty,
                "distinct_sources": self.distinct_sources}

    @classmethod
    def from_dict(cls, d: Dict) -> "SourceDigest":
        return cls(source_category=str(d.get("source_category", "")),
                   effectiveness=float(d.get("effectiveness", 0.0) or 0.0),
                   trust=float(d.get("trust", 0.0) or 0.0),
                   novelty=float(d.get("novelty", 0.0) or 0.0),
                   distinct_sources=int(d.get("distinct_sources", 0) or 0))


@dataclass
class VerificationDigest:
    # Dynamic labels (method / evidence-class names) are stored as VALUES, never as dict
    # keys — keeping every dict key a controlled field name so the metadata-only safety
    # guard can stay strict (a category named e.g. "secrets" must never sit in key position).
    method_success: List[Dict] = field(default_factory=list)
    evidence_class_success: List[Dict] = field(default_factory=list)
    verification_effectiveness: float = 0.0

    def to_dict(self) -> Dict:
        return {"method_success": sorted(self.method_success, key=lambda x: x["method"]),
                "evidence_class_success":
                    sorted(self.evidence_class_success, key=lambda x: x["evidence_class"]),
                "verification_effectiveness": self.verification_effectiveness}

    @classmethod
    def from_dict(cls, d: Dict) -> "VerificationDigest":
        return cls(method_success=[{"method": str(m.get("method", "")),
                                    "success_rate": float(m.get("success_rate", 0.0) or 0.0)}
                                   for m in (d.get("method_success") or [])],
                   evidence_class_success=[{"evidence_class": str(e.get("evidence_class", "")),
                                            "success_rate": float(e.get("success_rate", 0.0) or 0.0)}
                                           for e in (d.get("evidence_class_success") or [])],
                   verification_effectiveness=float(d.get("verification_effectiveness", 0.0) or 0.0))


@dataclass
class PluginDigest:
    plugin_capability_count: int = 0
    plugin_adapter_count: int = 0
    effective_capabilities: int = 0
    # category labels live as VALUES (list of {category,count}), never as dict keys.
    ecosystem_coverage: List[Dict] = field(default_factory=list)
    plugin_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {"plugin_capability_count": self.plugin_capability_count,
                "plugin_adapter_count": self.plugin_adapter_count,
                "effective_capabilities": self.effective_capabilities,
                "ecosystem_coverage": sorted(self.ecosystem_coverage,
                                             key=lambda x: x["category"]),
                "plugin_ids": sorted(self.plugin_ids)}

    @classmethod
    def from_dict(cls, d: Dict) -> "PluginDigest":
        return cls(plugin_capability_count=int(d.get("plugin_capability_count", 0) or 0),
                   plugin_adapter_count=int(d.get("plugin_adapter_count", 0) or 0),
                   effective_capabilities=int(d.get("effective_capabilities", 0) or 0),
                   ecosystem_coverage=[{"category": str(c.get("category", "")),
                                        "count": int(c.get("count", 0) or 0)}
                                       for c in (d.get("ecosystem_coverage") or [])],
                   plugin_ids=sorted(str(p) for p in (d.get("plugin_ids") or [])))


class KnowledgeDigestGenerator:
    """Builds anonymized digests from the local stores. Every store is optional and lazily
    constructed; with empty/default stores the structure is still fully populated (counts 0),
    so the generator is robust offline and deterministic."""

    def __init__(self, registry=None, catalog=None, source_store=None,
                 verification_store=None, tool_health_store=None,
                 capability_registry=None, node_name: str = "local", endpoint: str = ""):
        self._registry = registry
        self._catalog = catalog
        self._source_store = source_store
        self._verification_store = verification_store
        self._tool_health_store = tool_health_store
        self._capability_registry = capability_registry
        self.node_name = node_name or "local"
        self.endpoint = endpoint
        self.origin_peer_id = deterministic_id(
            "peer", self.node_name.strip().lower(), self.endpoint.strip().lower())

    # ── lazy store resolution (kept import-local so the package loads stand-alone) ──
    def _eff_catalog(self):
        if self._catalog is None:
            from hydra.plugins.plugin_catalog import EffectiveCapabilityCatalog
            from hydra.plugins.plugin_registry import PluginRegistry
            self._registry = self._registry or PluginRegistry()
            self._catalog = EffectiveCapabilityCatalog(self._registry).load()
        return self._catalog

    def _plugin_registry(self):
        if self._registry is None:
            from hydra.plugins.plugin_registry import PluginRegistry
            self._registry = PluginRegistry()
        return self._registry

    def _sources(self):
        if self._source_store is None:
            from hydra.capabilities.source_learning import SourceLearningStore
            self._source_store = SourceLearningStore()
        return self._source_store

    def _verification(self):
        if self._verification_store is None:
            from hydra.knowledge.verification import VerificationLearningStore
            self._verification_store = VerificationLearningStore()
        return self._verification_store

    def _health(self):
        if self._tool_health_store is None:
            from hydra.adapters.tool_health import ToolHealthStore
            self._tool_health_store = ToolHealthStore()
        return self._tool_health_store

    def _category_of(self) -> Dict[str, str]:
        """source.id → category from the capability registry (mirrors mcp_server)."""
        try:
            if self._capability_registry is None:
                from hydra.capabilities.registry import CapabilityRegistry
                self._capability_registry = CapabilityRegistry().load()
            out: Dict[str, str] = {}
            for name in self._capability_registry.names():
                for s in self._capability_registry.get(name).sources:
                    cat = s.category.value if hasattr(s.category, "value") else str(s.category)
                    out.setdefault(s.id, cat)
            return out
        except Exception:                       # offline robustness: no categories → bucketed
            return {}

    # ── digests ────────────────────────────────────────────────────────────────
    def capability_digests(self) -> List[CapabilityDigest]:
        catalog = self._eff_catalog()
        # Aggregate adapter health per capability (adapter_id == "capability::tool").
        exercise: Dict[str, int] = {}
        eff_sum: Dict[str, float] = {}
        eff_n: Dict[str, int] = {}
        for h in self._health().all_health():
            cap = h.adapter_id.split("::", 1)[0]
            if h.total_outcomes <= 0:
                continue
            exercise[cap] = exercise.get(cap, 0) + h.total_outcomes
            eff_sum[cap] = eff_sum.get(cap, 0.0) + h.reliability_score
            eff_n[cap] = eff_n.get(cap, 0) + 1
        out = []
        for c in catalog.all():
            cid = c.capability_id
            eff = round(eff_sum[cid] / eff_n[cid], 4) if eff_n.get(cid) else 0.0
            out.append(CapabilityDigest(
                capability_id=cid, category=c.category,
                exercise_count=exercise.get(cid, 0),
                verification_coverage=int(c.verification_coverage), effectiveness=eff))
        out.sort(key=lambda d: d.capability_id)
        return out

    def source_digests(self) -> List[SourceDigest]:
        category_of = self._category_of()
        agg: Dict[str, Dict[str, float]] = {}
        for s in self._sources().all_scores():
            cat = category_of.get(s.source_id, "uncategorized")
            a = agg.setdefault(cat, {"eff": 0.0, "trust": 0.0, "nov": 0.0, "n": 0})
            a["eff"] += s.effectiveness_score
            a["trust"] += s.trust_score
            a["nov"] += s.novelty_score
            a["n"] += 1
        out = []
        for cat in sorted(agg):
            a = agg[cat]
            n = max(1, int(a["n"]))
            out.append(SourceDigest(
                source_category=cat, effectiveness=round(a["eff"] / n, 4),
                trust=round(a["trust"] / n, 4), novelty=round(a["nov"] / n, 4),
                distinct_sources=int(a["n"])))
        return out

    def verification_digest(self) -> VerificationDigest:
        store = self._verification()
        method_success = [{"method": m["method"], "success_rate": float(m["success_rate"])}
                          for m in store.method_stats() if m.get("method")]
        evidence_success = [{"evidence_class": e["evidence_type"],
                             "success_rate": float(e["success_rate"])}
                            for e in store.by_evidence_type() if e.get("evidence_type")]
        rates = [m["success_rate"] for m in method_success]
        overall = round(sum(rates) / len(rates), 4) if rates else 0.0
        return VerificationDigest(method_success=method_success,
                                  evidence_class_success=evidence_success,
                                  verification_effectiveness=overall)

    def plugin_digest(self) -> PluginDigest:
        reg = self._plugin_registry()
        catalog = self._eff_catalog()
        comp = catalog.composition()
        plugin_cap_ids = set(catalog.plugin_capability_ids())
        try:
            from hydra.adapters.adapter_registry import AdapterRegistry
            adapters = AdapterRegistry(catalog=catalog).load()
            adapter_count = sum(1 for a in adapters.all_adapters()
                                if a.capability_id in plugin_cap_ids)
        except Exception:
            adapter_count = 0
        coverage: Dict[str, int] = {}
        for c in catalog.all():
            if c.capability_id in plugin_cap_ids:
                coverage[c.category] = coverage.get(c.category, 0) + 1
        return PluginDigest(
            plugin_capability_count=comp.get("plugin", 0),
            plugin_adapter_count=adapter_count,
            effective_capabilities=comp.get("effective", 0),
            ecosystem_coverage=[{"category": k, "count": v} for k, v in sorted(coverage.items())],
            plugin_ids=sorted(p.plugin_id for p in reg.enabled_plugins()))

    # ── envelope ─────────────────────────────────────────────────────────────────
    def generate(self, now: float = 0.0) -> Dict:
        """Produce the full, anonymized, deterministic digest envelope."""
        envelope = {
            "schema_version": DIGEST_SCHEMA_VERSION,
            "origin_peer_id": self.origin_peer_id,
            "generated_at": float(now),
            "capability_digests": [d.to_dict() for d in self.capability_digests()],
            "source_digests": [d.to_dict() for d in self.source_digests()],
            "verification_digest": self.verification_digest().to_dict(),
            "plugin_digest": self.plugin_digest().to_dict(),
        }
        assert_safe(envelope, where="exported digest")
        return envelope
