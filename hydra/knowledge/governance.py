"""
Knowledge Governance, Drift Detection & Quality Assurance (Phase J).

A fully DERIVED, NON-CANONICAL, read-only governance layer that continuously evaluates
the health, freshness, consistency and quality of the knowledge base. It reads the
canonical wiki (via `wiki_store`/`graph_index`) and the derived learning stores, and
emits ADVISORY reports + deterministic health scores.

Hard invariants: the wiki is never written; promotion.py / confidence.py are untouched;
no dual-write; no autonomous actions. Snapshots live in a derived, disposable,
rebuildable store under `data/knowledge_governance.db` (WAL, event-sourced). All
analytics are deterministic given the current canonical/learning state (+ injected `now`).
"""

from __future__ import annotations

import os
import sqlite3
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from hydra.capabilities.capability_catalog import CapabilityCatalog
from hydra.capabilities.source_learning import SourceLearningStore, recency_factor
from hydra.capabilities.tool_selection import CapabilityCoverage
from hydra.knowledge.graph_index import KnowledgeGraphIndex
from hydra.knowledge.schema import NodeType
from hydra.knowledge.signatures import DEFAULT_PROVIDER
from hydra.knowledge.verification import VerificationLearningStore
from hydra.knowledge.wiki_store import WikiStore

_DEFAULT_DB = Path(__file__).resolve().parents[2] / "data" / "knowledge_governance.db"
_DAY = 86400.0

# Staleness thresholds (days).
STALE_DAYS = {"pattern": 120, "chain": 90, "finding": 45, "intel": 180, "source": 90}
_VALIDATED = {"confirmed", "submitted", "accepted", "resolved"}
_REJECTED = {"rejected", "na", "duplicate"}


def _age_days(updated: Optional[str], now: float) -> Optional[float]:
    """Age in days from a 'YYYY-MM-DD' `updated` date. None if unparseable."""
    if not updated:
        return None
    try:
        t = time.mktime(time.strptime(str(updated)[:10], "%Y-%m-%d"))
    except Exception:
        return None
    return max(0.0, (now - t) / _DAY)


# ── Governance store (event-sourced snapshots; derived/disposable) ──────────────
class KnowledgeGovernanceStore:
    def __init__(self, db_path: Optional[Path | str] = None):
        self.db_path = Path(db_path) if db_path else Path(
            os.environ.get("HYDRA_GOVERNANCE_DB") or _DEFAULT_DB)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _conn(self):
        c = sqlite3.connect(str(self.db_path), timeout=30)
        c.row_factory = sqlite3.Row
        return c

    def _init(self):
        c = self._conn()
        try:
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA synchronous=NORMAL")
            c.executescript("""
                CREATE TABLE IF NOT EXISTS governance_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    metric TEXT NOT NULL, value REAL NOT NULL, taken_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_gov_metric ON governance_snapshots(metric);
            """)
            c.commit()
        finally:
            c.close()

    def record_snapshot(self, metrics: Dict[str, float]) -> None:
        """Append a governance snapshot (one row per metric). Enables trend/drift."""
        now = time.time()
        c = self._conn()
        try:
            c.executemany("INSERT INTO governance_snapshots (metric, value, taken_at) VALUES (?,?,?)",
                          [(k, float(v), now) for k, v in metrics.items()])
            c.commit()
        finally:
            c.close()

    def history(self, metric: str) -> List[float]:
        c = self._conn()
        try:
            return [r["value"] for r in c.execute(
                "SELECT value FROM governance_snapshots WHERE metric=? ORDER BY taken_at, id",
                (metric,)).fetchall()]
        finally:
            c.close()

    def trend(self, metric: str) -> Optional[float]:
        """Delta between the two most recent snapshots (latest - previous). None if <2."""
        h = self.history(metric)
        return round(h[-1] - h[-2], 4) if len(h) >= 2 else None

    def reset(self):
        c = self._conn()
        try:
            c.execute("DELETE FROM governance_snapshots")
            c.commit()
        finally:
            c.close()


# ── reports ─────────────────────────────────────────────────────────────────────
@dataclass
class DriftFinding:
    entity: str
    entity_type: str
    kind: str
    severity: str       # high | medium | low
    confidence: str     # high | medium | low
    rationale: str
    suggested_action: str

    def to_dict(self):
        return self.__dict__.copy()


@dataclass
class KnowledgeHealthScore:
    score: float
    components: Dict[str, float] = field(default_factory=dict)

    def to_dict(self):
        return {"score": self.score, "components": self.components}


# ── core analytics (read-only over canonical + learning) ────────────────────────
class _GovernanceBase:
    def __init__(self, store: Optional[WikiStore] = None,
                 index: Optional[KnowledgeGraphIndex] = None,
                 learning: Optional[SourceLearningStore] = None,
                 verification: Optional[VerificationLearningStore] = None,
                 catalog: Optional[CapabilityCatalog] = None,
                 now: Optional[float] = None,
                 pages: Optional[Dict[str, list]] = None):
        self.store = store or WikiStore()
        self.index = index or KnowledgeGraphIndex.build(self.store)
        self.learning = learning or SourceLearningStore()
        self.verification = verification or VerificationLearningStore()
        self.catalog = (catalog or CapabilityCatalog()).load()
        self.now = now if now is not None else time.time()
        self._pages_cache = pages   # {node_type_value: [WikiPage]} — read the wiki once

    def _pages(self, ntype: Optional[NodeType] = None) -> list:
        """All pages (or one type) from a single cached wiki read — shared across the
        many sub-analyses a governance summary performs (avoids re-reading every file)."""
        if self._pages_cache is None:
            cache: Dict[str, list] = {}
            for p in self.store.list_pages():
                cache.setdefault(p.type.value if p.type else "unknown", []).append(p)
            self._pages_cache = cache
        if ntype is None:
            return [p for lst in self._pages_cache.values() for p in lst]
        return self._pages_cache.get(ntype.value, [])

    def _shared(self) -> Dict:
        """Kwargs to construct a sub-analyzer that reuses this one's index + page cache."""
        self._pages()   # ensure cache built once
        return dict(store=self.store, index=self.index, learning=self.learning,
                    verification=self.verification, catalog=self.catalog,
                    now=self.now, pages=self._pages_cache)


class GraphHealth(_GovernanceBase):
    def report(self) -> Dict:
        nodes = self.index.nodes
        n = len(nodes)
        edges = len(self.index.edges)
        orphans = self.index.orphans()
        # connected components over the undirected link view
        seen, components = set(), 0
        for start in nodes:
            if start in seen:
                continue
            components += 1
            seen.add(start)
            q = deque([start])
            while q:
                for nb in self.index.neighbors(q.popleft()):
                    if nb not in seen:
                        seen.add(nb)
                        q.append(nb)
        avg_degree = round((2 * edges) / n, 3) if n else 0.0
        density = round(edges / (n * (n - 1)), 5) if n > 1 else 0.0
        clustered = sum(1 for x in nodes if len(self.index.neighbors(x)) >= 2)
        by_type = self.index.by_type()
        chains = len(by_type.get("chain", []))
        return {
            "nodes": n, "edges": edges, "avg_degree": avg_degree, "density": density,
            "orphan_nodes": orphans, "orphan_count": len(orphans),
            "disconnected_components": components,
            "clustered_node_ratio": round(clustered / n, 3) if n else 0.0,
            "chain_count": chains,
            "attack_chain_concentration": round(chains / max(len(by_type.get("finding", [])), 1), 3),
            "dangling_links": len(self.index.dangling_links()),
        }


class DriftDetector(_GovernanceBase):
    def report(self) -> Dict:
        findings: List[DriftFinding] = []

        # stale patterns / chains / intel by age
        for ntype, key in ((NodeType.PATTERN, "pattern"), (NodeType.CHAIN, "chain"),
                           (NodeType.INTEL, "intel")):
            for p in self._pages(ntype):
                age = _age_days(p.meta.get("updated"), self.now)
                thr = STALE_DAYS[key]
                if age is not None and age > thr:
                    sev = "high" if age > 2 * thr else "medium"
                    findings.append(DriftFinding(
                        p.slug, key, f"stale_{key}", sev, "high",
                        f"{key} not updated in {int(age)}d (> {thr}d threshold)",
                        f"review/revalidate this {key}"))

        # stale suspected findings
        for p in self._pages(NodeType.FINDING):
            status = str(p.meta.get("status", "")).lower()
            age = _age_days(p.meta.get("updated"), self.now)
            if status in ("suspected", "submitted") and age is not None and age > STALE_DAYS["finding"]:
                findings.append(DriftFinding(
                    p.slug, "finding", "stale_finding", "medium", "medium",
                    f"{status} finding unresolved for {int(age)}d", "re-verify or update status"))

        # source decay + declining effectiveness
        for s in self.learning.all_scores():
            decay = recency_factor(s.last_success_at, self.now)
            if s.last_success_at and decay < 0.25:
                findings.append(DriftFinding(
                    s.source_id, "source", "stale_source", "medium", "medium",
                    f"no successful contribution recently (recency factor {decay:.2f})",
                    "re-exercise or de-prioritize this source"))
            if s.discoveries >= 5 and s.effectiveness_score < 0.2:
                findings.append(DriftFinding(
                    s.source_id, "source", "declining_source_effectiveness", "high", "high",
                    f"effectiveness {s.effectiveness_score} over {s.discoveries} discoveries",
                    "investigate source quality / reduce reliance"))

        # declining verification success
        for m in self.verification.method_stats():
            if m["attempts"] >= 5 and m["success_rate"] < 0.3:
                findings.append(DriftFinding(
                    m["method"], "verification_method", "declining_verification_success",
                    "high", "high",
                    f"success rate {m['success_rate']} over {m['attempts']} attempts",
                    "review verification method / evidence requirements"))

        # capability drift (unused capabilities)
        cov = CapabilityCoverage(self.catalog, self.learning, self.verification).report()
        for cid in cov["uncovered_capabilities"][:25]:   # bounded, deterministic
            findings.append(DriftFinding(
                cid, "capability", "capability_drift", "low", "medium",
                "capability has no exercise history", "exercise or retire this capability"))

        findings.sort(key=lambda f: ({"high": 0, "medium": 1, "low": 2}[f.severity], f.kind, f.entity))
        sev_counts: Dict[str, int] = {}
        for f in findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
        return {"drift_count": len(findings), "by_severity": sev_counts,
                "findings": [f.to_dict() for f in findings]}


class KnowledgeQualityAnalyzer(_GovernanceBase):
    def _duplicate_pattern_groups(self) -> Dict[str, List[str]]:
        groups: Dict[str, List[str]] = {}
        for p in self._pages(NodeType.PATTERN):
            sig = DEFAULT_PROVIDER.signature(p)
            if sig:
                groups.setdefault(sig, []).append(p.slug)
        return {sig: sorted(slugs) for sig, slugs in groups.items() if len(slugs) > 1}

    def _contradictions(self) -> List[Dict]:
        by_host: Dict[str, Dict[str, List[str]]] = {}
        for p in self._pages(NodeType.FINDING):
            host = str(p.meta.get("host") or "")
            if not host:
                continue
            status = str(p.meta.get("status", "")).lower()
            b = by_host.setdefault(host, {"validated": [], "rejected": []})
            if status in _VALIDATED:
                b["validated"].append(p.slug)
            elif status in _REJECTED:
                b["rejected"].append(p.slug)
        out = []
        for host, b in sorted(by_host.items()):
            if b["validated"] and b["rejected"]:
                out.append({"host": host, "validated": sorted(b["validated"]),
                            "rejected": sorted(b["rejected"])})
        return out

    def _stale_ratio(self) -> float:
        total = stale = 0
        for ntype, key in ((NodeType.PATTERN, "pattern"), (NodeType.CHAIN, "chain"),
                           (NodeType.FINDING, "finding"), (NodeType.INTEL, "intel")):
            for p in self._pages(ntype):
                total += 1
                age = _age_days(p.meta.get("updated"), self.now)
                if age is not None and age > STALE_DAYS[key]:
                    stale += 1
        return round(stale / total, 4) if total else 0.0

    def metrics(self) -> Dict:
        patterns = self._pages(NodeType.PATTERN)
        findings = self._pages(NodeType.FINDING)
        dup_groups = self._duplicate_pattern_groups()
        dup_count = sum(len(v) for v in dup_groups.values())
        contradictions = self._contradictions()

        verified_classes = {m["vuln_class"] for m in self.verification.by_vuln_class()}
        seen_classes = {DEFAULT_PROVIDER.signature(p) for p in findings} - {""}
        sources_with_events = len([s for s in self.learning.all_scores() if s.total_events > 0])
        declared_tools = len(self.catalog.all_tools())
        cov = CapabilityCoverage(self.catalog, self.learning, self.verification).report()
        exercised_caps = cov["total_capabilities"] - cov["uncovered_count"]

        return {
            "duplication_rate": round(dup_count / max(len(patterns), 1), 4),
            "contradiction_rate": round(len(contradictions) / max(len(findings), 1), 4),
            "stale_ratio": self._stale_ratio(),
            "verification_coverage": round(len(verified_classes) / max(len(seen_classes), 1), 4)
                                     if seen_classes else 0.0,
            "source_diversity": round(sources_with_events / max(declared_tools, 1), 4),
            "capability_coverage": round(exercised_caps / max(cov["total_capabilities"], 1), 4),
            "duplicate_groups": dup_groups,
            "contradictions": contradictions,
        }

    def health_score(self) -> KnowledgeHealthScore:
        m = self.metrics()
        gh = GraphHealth(**self._shared()).report()
        orphan_ratio = gh["orphan_count"] / gh["nodes"] if gh["nodes"] else 0.0
        graph_health = round(0.5 * (1 - orphan_ratio) + 0.5 * gh["clustered_node_ratio"], 4)
        components = {
            "duplication_health": round(1 - min(1.0, m["duplication_rate"]), 4),
            "contradiction_health": round(1 - min(1.0, m["contradiction_rate"]), 4),
            "freshness": round(1 - m["stale_ratio"], 4),
            "verification_coverage": min(1.0, m["verification_coverage"]),
            "source_diversity": min(1.0, m["source_diversity"]),
            "capability_coverage": min(1.0, m["capability_coverage"]),
            "graph_health": graph_health,
        }
        # equal-weight blend → [0,100], deterministic
        score = round(100 * sum(components.values()) / len(components), 1)
        return KnowledgeHealthScore(score=score, components=components)


# ── intelligence + lifecycle (read-only) ────────────────────────────────────────
class GovernanceIntelligence(_GovernanceBase):
    def stale_entities(self) -> List[Dict]:
        return [f for f in DriftDetector(**self._shared()).report()["findings"]
                if f["kind"].startswith("stale")]

    def duplicate_patterns(self) -> Dict[str, List[str]]:
        return KnowledgeQualityAnalyzer(**self._shared())._duplicate_pattern_groups()

    def contradiction_report(self) -> List[Dict]:
        return KnowledgeQualityAnalyzer(**self._shared())._contradictions()

    def decision_intelligence(self) -> Dict:
        """Phase-L decision-intelligence health (simulation_health / prediction_quality /
        decision_drift). Read-only; lazy import keeps governance robust if the layer is
        absent. Never alters confidence/promotion."""
        try:
            from hydra.intelligence.simulation import PredictionAnalytics
            return PredictionAnalytics().health()
        except Exception:
            return {"simulation_health": None, "prediction_quality": "unknown",
                    "decision_drift": None, "matched_samples": 0}

    def temporal_intelligence(self) -> Dict:
        """Phase-O temporal-intelligence health (temporal_health_score / rising vs declining
        trends / decay / anomalies). Read-only; lazy import keeps governance robust if the
        layer is absent. Never alters confidence/promotion or the wiki."""
        try:
            from hydra.temporal_intel.intelligence import TemporalIntelligence
            return TemporalIntelligence().temporal_health()
        except Exception:
            return {"temporal_health_score": None, "status": "unknown", "total_events": 0}

    def offensive_intelligence(self) -> Dict:
        """Phase-P offensive-intelligence health (offensive_health_score / mean effectiveness /
        coverage quality / redundancy). Read-only; lazy import keeps governance robust if the
        layer is absent. Never alters confidence/promotion or the wiki."""
        try:
            from hydra.offensive_intel.intelligence import OffensiveIntelligence
            return OffensiveIntelligence().offensive_health()
        except Exception:
            return {"offensive_health_score": None, "status": "unknown", "total_events": 0}

    def campaign_intelligence(self) -> Dict:
        """Phase-Q campaign-intelligence health (campaign_health_score / phase & playbook
        effectiveness / coverage). Read-only; lazy import keeps governance robust if the layer is
        absent. Never alters confidence/promotion or the wiki; NON-executing."""
        try:
            from hydra.campaigns.intelligence import CampaignIntelligence
            return CampaignIntelligence().campaign_health()
        except Exception:
            return {"campaign_health_score": None, "status": "unknown", "total_events": 0}

    def skill_intelligence(self) -> Dict:
        """Phase-R skill-intelligence health (skill_health_score / mean skill effectiveness /
        capability coverage / graph connectivity). Read-only; lazy import keeps governance robust if
        the layer is absent. Never alters confidence/promotion or the wiki; NON-executing."""
        try:
            from hydra.skill_intel.intelligence import SkillGraphIntelligence
            return SkillGraphIntelligence().skill_health()
        except Exception:
            return {"skill_health_score": None, "status": "unknown", "total_events": 0}

    def opportunity_intelligence(self) -> Dict:
        """Phase-S opportunity-intelligence health (opportunity_health_score / synthesized coverage /
        surface breadth / coverage realization / blind-spot health). Read-only; lazy import keeps
        governance robust if the layer is absent. Never alters confidence/promotion or the wiki;
        NON-executing."""
        try:
            from hydra.opportunity_intel.intelligence import OpportunityIntelligence
            return OpportunityIntelligence().opportunity_health()
        except Exception:
            return {"opportunity_health_score": None, "status": "unknown", "total_events": 0}

    @staticmethod
    def _rank(components: Dict[str, float]):
        return sorted(components.items(), key=lambda kv: (kv[1], kv[0]))

    def _component_ranking(self):
        return self._rank(KnowledgeQualityAnalyzer(**self._shared()).health_score().components)

    def weakest_areas(self) -> List[Dict]:
        return [{"area": k, "score": v} for k, v in self._component_ranking()[:3]]

    def healthiest_areas(self) -> List[Dict]:
        return [{"area": k, "score": v} for k, v in self._component_ranking()[-3:][::-1]]

    def governance_summary(self) -> Dict:
        # Compute each derived view once over a single shared wiki read + graph index.
        qa = KnowledgeQualityAnalyzer(**self._shared())
        health = qa.health_score()
        ranked = self._rank(health.components)
        drift = DriftDetector(**self._shared()).report()
        graph = GraphHealth(**self._shared()).report()
        return {
            "knowledge_health_score": health.score,
            "health_components": health.components,
            "drift": {"count": drift["drift_count"], "by_severity": drift["by_severity"]},
            "weakest_areas": [{"area": k, "score": v} for k, v in ranked[:3]],
            "healthiest_areas": [{"area": k, "score": v} for k, v in ranked[-3:][::-1]],
            "graph": {"nodes": graph["nodes"], "orphans": graph["orphan_count"],
                      "components": graph["disconnected_components"], "density": graph["density"]},
            "decision_intelligence": self.decision_intelligence(),
            "temporal_intelligence": self.temporal_intelligence(),
            "offensive_intelligence": self.offensive_intelligence(),
            "campaign_intelligence": self.campaign_intelligence(),
            "skill_intelligence": self.skill_intelligence(),
            "opportunity_intelligence": self.opportunity_intelligence(),
            "recommendations": LifecycleAdvisor(**self._shared()).recommendations(),
        }


class LifecycleAdvisor(_GovernanceBase):
    def recommendations(self) -> List[Dict]:
        """Advisory recommendations only — no actions are taken."""
        recs: List[Dict] = []
        drift = DriftDetector(**self._shared()).report()
        # one recommendation per high/medium drift finding (bounded)
        for f in drift["findings"]:
            if f["severity"] in ("high", "medium"):
                recs.append({"target": f["entity"], "type": f["kind"],
                             "severity": f["severity"], "recommendation": f["suggested_action"]})
        qa = KnowledgeQualityAnalyzer(**self._shared()).metrics()
        if qa["verification_coverage"] < 0.5:
            recs.append({"target": "verification", "type": "coverage",
                         "severity": "medium", "recommendation": "verification coverage insufficient — add verification events"})
        if qa["duplicate_groups"]:
            recs.append({"target": "patterns", "type": "duplication",
                         "severity": "low", "recommendation": "review duplicate pattern candidates for consolidation"})
        return recs[:50]
