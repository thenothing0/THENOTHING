"""
Phase U — Threat Intelligence & Knowledge Fusion tests.

Deterministic, store-free, NON-executing. Asserts the fused Threat model, the fully-explainable
Threat→Campaign→Technique→Capability→Skill→Agent graph (every edge carries a reason), deterministic
clustering, temporal threat evolution, the four fusion linkers (adversary/campaign/skill/opportunity),
bounded risk + 0-100 threat-health, the shared P/Q/R/S/T load, rebuild-identical determinism, and the
protected-core invariants.
"""

import json
import pathlib

import pytest

import hydra.knowledge.confidence as confidence_mod
import hydra.knowledge.promotion as promotion_mod
from hydra.threat_intel import (
    AdversaryLinker,
    CampaignLinker,
    OpportunityLinker,
    SkillLinker,
    ThreatContext,
    ThreatEvolution,
    ThreatGraph,
    ThreatIntelligence,
    ThreatModel,
    ThreatRiskScorer,
)
from hydra.threat_intel.advisor import SAFE_VERBS, ThreatAdvisor
from hydra.threat_intel.util import THREAT_SCORING_VERSION


@pytest.fixture
def cold(tmp_path, monkeypatch):
    monkeypatch.setenv("HYDRA_TOOL_HEALTH_DB", str(tmp_path / "nope_th.db"))
    monkeypatch.setenv("HYDRA_VERIFICATION_DB", str(tmp_path / "nope_vr.db"))
    return ThreatContext()


# ── threat model ─────────────────────────────────────────────────────────────────
def test_threats_one_per_tactic(cold):
    threats = ThreatModel(cold).threats()
    assert len(threats) == 14                          # one per ATT&CK Enterprise tactic
    in_scope = [t for t in threats if not t.model_only]
    assert {t.threat_id for t in in_scope} == {"TA0043", "TA0001", "TA0006", "TA0007"}
    # model-only threats carry no risk score and are out_of_scope (never a fixable risk)
    for t in threats:
        if t.model_only:
            assert t.risk_score is None and t.risk_status == "out_of_scope"


def test_threat_fusion_fields(cold):
    t = ThreatModel(cold).get("TA0043")
    assert t.capabilities and t.skills and t.agents          # fused from P/R/ownership
    assert 0.0 <= t.coverage_ratio <= 1.0
    assert 0.0 <= t.opportunity_gap <= 1.0                    # Phase-S signal
    assert 0.0 <= (t.risk_score or 0.0) <= 1.0
    # risk reconstructs from explainable components (within rounding) unless clamped
    comp_sum = round(sum(t.components.values()), 4)
    assert abs((t.risk_score or 0.0) - comp_sum) <= 0.001 or t.risk_score in (0.0, 1.0)


def test_unknown_threat(cold):
    assert ThreatModel(cold).get("TZZZ") is None
    assert ThreatModel(cold).report(threat_id="TZZZ")["error"] == "unknown threat"


# ── threat graph (explainability) ────────────────────────────────────────────────
def test_graph_every_edge_explained(cold):
    g = ThreatGraph(cold).build()
    assert g["edge_count"] >= 1 and g["node_count"] >= 1
    valid_types = {"threat", "campaign", "technique", "capability", "skill", "agent"}
    for e in g["edges"]:
        assert e["from_type"] in valid_types and e["to_type"] in valid_types
        assert e["reason"], "every edge must carry a non-empty reason (no hidden inference)"
        assert e["relation"]
    # the full fusion chain is represented
    assert set(g["node_counts"]) == valid_types
    assert g["node_counts"]["threat"] == 4


def test_graph_subgraph_and_unknown(cold):
    tg = ThreatGraph(cold)
    sub = tg.report(threat_id="TA0043")
    assert sub["edge_count"] >= 1
    assert all("reason" in e for e in sub["edges"])
    assert tg.report(threat_id="TZZZ")["error"] == "unknown threat"


# ── clustering (deterministic + explainable) ─────────────────────────────────────
def test_clusters_partition_and_explained(cold):
    clusters = ThreatModel(cold).clusters()
    members = [t for c in clusters for t in c["threats"]]
    assert len(members) == len(set(members))           # each threat in exactly one cluster
    assert set(members) == {"TA0043", "TA0001", "TA0006", "TA0007"}
    for c in clusters:
        assert c["reason"]
        assert c["threats"] == sorted(c["threats"])


def test_cluster_stability(cold):
    a = ThreatModel(ThreatContext()).clusters()
    b = ThreatModel(ThreatContext()).clusters()
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


# ── evolution (O + T fusion) ─────────────────────────────────────────────────────
def test_evolution_stable_when_no_temporal(cold):
    rep = ThreatEvolution(cold).report()
    # cold-start: no temporal store → every threat is stable (honest default, no fabricated trend)
    assert set(rep["stable"]) == {"TA0043", "TA0001", "TA0006", "TA0007"}
    assert rep["rising"] == [] and rep["declining"] == []
    assert rep["temporal_data"] is False


# ── linkers (fusion reports) ─────────────────────────────────────────────────────
def test_adversary_linking(cold):
    rep = AdversaryLinker(cold).report()
    assert rep["profiles"] and rep["threats"]
    for p in rep["profiles"]:
        assert p["threat_count"] == len(p["threats"])


def test_campaign_linking(cold):
    rep = CampaignLinker(cold).report()
    assert rep["count"] >= 1
    for r in rep["campaign_phases"]:
        assert 0.0 <= r["mean_coverage"] <= 1.0


def test_skill_linking(cold):
    rep = SkillLinker(cold).report()
    assert rep["most_critical_skills"]
    for r in rep["skills"]:
        assert r["threat_count"] == len(r["threats"])


def test_opportunity_linking(cold):
    rep = OpportunityLinker(cold).report()
    for t in rep["exposed_threats"]:
        assert 0.0 <= (t["risk_score"] or 0.0) <= 1.0
    for o in rep["risk_closing_opportunities"]:
        assert o["risk_closed"] >= 0.0
        assert o["threat_count"] == len(o["threats_helped"])


# ── risk + health ────────────────────────────────────────────────────────────────
def test_health_bounded_six_inputs(cold):
    h = ThreatRiskScorer(cold).threat_health()
    assert 0.0 <= h["threat_health_score"] <= 100.0
    assert h["status"] in ("healthy", "watch", "degrading")
    for k in ("coverage", "resilience", "diversity", "mean_opportunity_gap",
              "mean_decay", "federation_consensus"):
        assert k in h
    assert h["data_mode"] == "catalog_only"
    assert h["scoring_version"] == THREAT_SCORING_VERSION


def test_risk_ranked(cold):
    rep = ThreatRiskScorer(cold).ranked_risks()
    scores = [r["risk_score"] for r in rep["risks"]]
    assert scores == sorted(scores, reverse=True)
    assert all(0.0 <= s <= 1.0 for s in scores)


# ── advisor (safe verbs only) ────────────────────────────────────────────────────
def test_advisor_bounded_and_safe(cold):
    recs = ThreatAdvisor(cold).recommendations(limit=8)
    assert len(recs) <= 8
    for rec in recs:
        assert rec["type"] in SAFE_VERBS
        assert rec["suggested_action"].split()[0].lower() in SAFE_VERBS
        for unsafe in ("execute", "attack", "emulate", "collect", "deploy"):
            assert not rec["suggested_action"].lower().startswith(unsafe)
        assert rec["advisory"] is True
        assert 0.0 <= rec["confidence"] <= 1.0


# ── summary + shared load ────────────────────────────────────────────────────────
def test_summary_shape(cold):
    s = ThreatIntelligence(cold).threat_summary()
    assert s["advisory"] is True
    assert s["scoring_version"] == THREAT_SCORING_VERSION
    for k in ("threat_health", "threats", "graph", "clusters", "evolution",
              "broadest_adversary_profiles", "recommendations"):
        assert k in s


def test_shared_offensive_load(cold):
    # P/Q/R/S/T all reachable through ONE OffensiveIntelligence
    assert cold.adversary().ac.oi is cold.oi             # Phase T
    assert cold.opportunity().oc.oi is cold.oi           # Phase S
    assert cold.campaign().cc.oi is cold.oi              # Phase Q
    assert cold.skill().cc.oi is cold.oi                 # Phase R
    assert cold.mapping()._ctx is cold.ctx               # ATT&CK mapping shares the ctx


# ── determinism / invariants ─────────────────────────────────────────────────────
def test_deterministic_rebuild_identical():
    a = ThreatIntelligence().threat_summary(now=6160.0)
    b = ThreatIntelligence().threat_summary(now=6160.0)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_graph_deterministic():
    a = ThreatIntelligence().threat_graph(now=1.0)
    b = ThreatIntelligence().threat_graph(now=1.0)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_store_free():
    pkg = pathlib.Path(__file__).resolve().parents[2] / "hydra" / "threat_intel"
    for p in sorted(pkg.glob("*.py")):
        assert "sqlite3" not in p.read_text(encoding="utf-8"), \
            f"threat_intel must be store-free (sqlite3 in {p.name})"


def test_no_execution_or_canonical_imports():
    pkg = pathlib.Path(__file__).resolve().parents[2] / "hydra" / "threat_intel"
    exec_forbidden = ["subprocess", "os.system", "popen", "requests.", "urllib.request",
                      "socket.", "exec(", "eval("]
    import_forbidden = ["promotion", "confidence", "wiki_store", "WikiStore", "wiki_writer"]
    for p in sorted(pkg.glob("*.py")):
        lines = p.read_text(encoding="utf-8").splitlines()
        full = "\n".join(lines)
        for token in exec_forbidden:
            assert token not in full, f"forbidden '{token}' in threat_intel/{p.name}"
        for line in lines:
            s = line.strip()
            if s.startswith(("import ", "from ")):
                for token in import_forbidden:
                    assert token not in line, \
                        f"forbidden import '{token}' in threat_intel/{p.name}: {s}"


def test_promotion_confidence_untouched():
    assert confidence_mod.score_from_sources(["a", "b"], {"a": 0.7, "b": 0.7}).value == "high"
    assert hasattr(promotion_mod, "apply_promotion")
