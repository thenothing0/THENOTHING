"""Phase J — governance: drift, quality, health, graph, intelligence (deterministic, read-only)."""

import time

from hydra.capabilities.source_learning import EV_DISCOVERY, SourceLearningStore
from hydra.knowledge.governance import (
    DriftDetector,
    GovernanceIntelligence,
    GraphHealth,
    KnowledgeGovernanceStore,
    KnowledgeQualityAnalyzer,
    LifecycleAdvisor,
)
from hydra.knowledge.schema import NodeType
from hydra.knowledge.verification import VerificationLearningStore
from hydra.knowledge.wiki_store import WikiStore

# A fixed "now" far enough ahead that freshly-written pages (updated=today) read as
# stale against the thresholds — lets us exercise staleness deterministically.
_FUTURE = time.time() + 400 * 86400
_NOWISH = time.time()


def _seed(tmp_path):
    ws = WikiStore(tmp_path / "wiki")
    ws.upsert(NodeType.TARGET, "acme", {"tags": ["t"]}, "# acme\nlinks [[idor-pattern]]\n")
    # duplicate patterns (same idor signature)
    ws.upsert(NodeType.PATTERN, "idor-pattern", {"tags": ["idor"], "vuln_class": "idor"},
              "# idor a\nseen on [[acme]]\n")
    ws.upsert(NodeType.PATTERN, "idor-pattern-2", {"tags": ["idor"], "vuln_class": "idor"},
              "# idor b\nseen on [[acme]]\n")
    # contradiction: same host validated + rejected
    ws.upsert(NodeType.FINDING, "f-confirmed",
              {"tags": ["idor"], "status": "confirmed", "host": "api.acme.com", "target": "[[acme]]"},
              "# confirmed\nidor\n")
    ws.upsert(NodeType.FINDING, "f-rejected",
              {"tags": ["idor"], "status": "rejected", "host": "api.acme.com", "target": "[[acme]]"},
              "# rejected\nidor\n")
    return ws


def _kw(tmp_path):
    return {"store": _seed(tmp_path),
            "learning": SourceLearningStore(tmp_path / "l.db"),
            "verification": VerificationLearningStore(tmp_path / "v.db")}


# ── quality + health ──────────────────────────────────────────────────────────
def test_quality_metrics(tmp_path):
    kw = _kw(tmp_path)
    m = KnowledgeQualityAnalyzer(now=_NOWISH, **kw).metrics()
    assert m["duplication_rate"] == 1.0          # 2/2 patterns share signature
    assert "idor" in m["duplicate_groups"]
    assert m["contradiction_rate"] == 0.5        # 1 contradiction / 2 findings
    assert m["contradictions"][0]["host"] == "api.acme.com"


def test_health_score_bounded_and_deterministic(tmp_path):
    kw = _kw(tmp_path)
    h1 = KnowledgeQualityAnalyzer(now=_NOWISH, **kw).health_score()
    h2 = KnowledgeQualityAnalyzer(now=_NOWISH, **kw).health_score()
    assert 0.0 <= h1.score <= 100.0
    assert h1.to_dict() == h2.to_dict()          # deterministic
    assert set(h1.components) >= {"duplication_health", "contradiction_health", "freshness",
                                  "verification_coverage", "graph_health"}


# ── drift / stale detection ─────────────────────────────────────────────────────
def test_stale_detection_with_future_now(tmp_path):
    kw = _kw(tmp_path)
    drift = DriftDetector(now=_FUTURE, **kw).report()
    kinds = {f["kind"] for f in drift["findings"]}
    assert "stale_pattern" in kinds              # patterns "updated today" are stale at +400d
    assert drift["drift_count"] > 0


def test_no_stale_when_fresh(tmp_path):
    kw = _kw(tmp_path)
    drift = DriftDetector(now=_NOWISH, **kw).report()
    assert not any(f["kind"] == "stale_pattern" for f in drift["findings"])


def test_declining_source_effectiveness_detected(tmp_path):
    kw = _kw(tmp_path)
    for _ in range(10):
        kw["learning"].record_source_event("source.flaky", EV_DISCOVERY)  # discoveries, no confirms
    drift = DriftDetector(now=_NOWISH, **kw).report()
    assert any(f["kind"] == "declining_source_effectiveness" and f["entity"] == "source.flaky"
               for f in drift["findings"])


def test_declining_verification_success_detected(tmp_path):
    kw = _kw(tmp_path)
    for _ in range(6):
        kw["verification"].record_verification("idor", "weak_verifier", "failure")
    drift = DriftDetector(now=_NOWISH, **kw).report()
    assert any(f["kind"] == "declining_verification_success" for f in drift["findings"])


# ── graph health ────────────────────────────────────────────────────────────────
def test_graph_health(tmp_path):
    kw = _kw(tmp_path)
    gh = GraphHealth(now=_NOWISH, **kw).report()
    assert gh["nodes"] >= 5
    assert gh["disconnected_components"] >= 1
    assert 0.0 <= gh["density"] <= 1.0
    assert "orphan_nodes" in gh


# ── intelligence read APIs ──────────────────────────────────────────────────────
def test_governance_intelligence_apis(tmp_path):
    kw = _kw(tmp_path)
    gi = GovernanceIntelligence(now=_NOWISH, **kw)
    assert "idor" in gi.duplicate_patterns()
    assert gi.contradiction_report()[0]["host"] == "api.acme.com"
    weak = {a["area"] for a in gi.weakest_areas()}
    assert weak and weak <= set(KnowledgeQualityAnalyzer(now=_NOWISH, **kw).health_score().components)
    summ = gi.governance_summary()
    assert set(summ) >= {"knowledge_health_score", "drift", "weakest_areas", "recommendations"}


def test_lifecycle_advisor_recommendations(tmp_path):
    kw = _kw(tmp_path)
    recs = LifecycleAdvisor(now=_NOWISH, **kw).recommendations()
    assert isinstance(recs, list)
    assert any(r["type"] == "duplication" for r in recs)   # duplicate patterns present


# ── store: event-sourced, rebuild-identical ─────────────────────────────────────
def test_governance_store_snapshots_and_trend(tmp_path):
    s = KnowledgeGovernanceStore(tmp_path / "g.db")
    s.record_snapshot({"health": 50.0})
    s.record_snapshot({"health": 60.0})
    assert s.history("health") == [50.0, 60.0]
    assert s.trend("health") == 10.0
    s.reset()
    assert s.history("health") == []


def test_health_rebuild_identical(tmp_path):
    # same canonical + learning state ⇒ identical health score (rebuildable)
    def run(tag):
        ws = _seed(tmp_path / tag)
        learn = SourceLearningStore(tmp_path / f"{tag}-l.db")
        ver = VerificationLearningStore(tmp_path / f"{tag}-v.db")
        return KnowledgeQualityAnalyzer(store=ws, learning=learn, verification=ver,
                                        now=_NOWISH).health_score().to_dict()
    assert run("a") == run("b")
