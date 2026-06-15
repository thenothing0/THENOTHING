"""
Phase S — Opportunity Intelligence tests.

Deterministic, store-free, NON-executing. Asserts the attack-surface model, fused coverage
synthesizer, severity-ranked blind spots, opportunity graph, the versioned OpportunityScore ranker
(bounded + explainable), the safe-verb advisor, bounded health, the shared Phase-P/Q/R load,
rebuild-identical determinism, and the protected-core invariants.
"""

import json
import pathlib

import pytest

import hydra.knowledge.confidence as confidence_mod
import hydra.knowledge.promotion as promotion_mod
from hydra.opportunity_intel import (
    AttackSurfaceModel,
    BlindSpotAnalyzer,
    CoverageSynthesizer,
    OpportunityAdvisor,
    OpportunityContext,
    OpportunityGraph,
    OpportunityIntelligence,
    OpportunityRanker,
)
from hydra.opportunity_intel.advisor import SAFE_VERBS
from hydra.opportunity_intel.util import OPPORTUNITY_SCORING_VERSION

CAPS = 153   # effective capabilities pinned by the repo (matches Phase-R coverage test)


@pytest.fixture
def cold(tmp_path, monkeypatch):
    monkeypatch.setenv("HYDRA_TOOL_HEALTH_DB", str(tmp_path / "nope_th.db"))
    monkeypatch.setenv("HYDRA_VERIFICATION_DB", str(tmp_path / "nope_vr.db"))
    return OpportunityContext()


# ── attack-surface model ─────────────────────────────────────────────────────────
def test_surface_totals(cold):
    rep = AttackSurfaceModel(cold).report()
    t = rep["totals"]
    assert t["total_capabilities"] == CAPS
    assert t["addressable_finding_types"] >= 1
    assert 0.0 <= rep["surface_breadth_index"] <= 1.0
    assert rep["advisory"] is True
    for r in rep["surface"]:
        assert 0.0 <= r["verification_coverage_pct"] <= 100.0
        assert r["finding_type_count"] == len(r["finding_types"])


# ── coverage synthesizer ─────────────────────────────────────────────────────────
def test_coverage_index_bounded(cold):
    rep = CoverageSynthesizer(cold).report()
    assert 0.0 <= rep["overall_coverage_index"] <= 1.0
    rows = rep["category_coverage"]
    assert len(rows) >= 1
    for c in rows:
        assert 0.0 <= c["coverage_index"] <= 1.0
        for dim in ("effectiveness", "verification_coverage", "exercise_coverage",
                    "agent_coverage", "skill_coverage"):
            assert 0.0 <= c[dim] <= 1.0
    # weakest first (ascending coverage_index)
    idxs = [c["coverage_index"] for c in rows]
    assert idxs == sorted(idxs)


# ── blind spots ──────────────────────────────────────────────────────────────────
def test_blindspots_typed_ranked_and_partitioned(cold):
    rep = BlindSpotAnalyzer(cold).report()
    assert rep["actionable_count"] + rep["intentional_count"] == rep["count"]
    sevs = [s["severity"] for s in rep["blind_spots"]]
    assert sevs == sorted(sevs, reverse=True)               # ranked by severity desc
    for s in rep["blind_spots"]:
        assert 0.0 <= s["severity"] <= 1.0
        assert isinstance(s["intentional"], bool)
        assert s["advisory"] is True
    # model-only campaign phases are flagged INTENTIONAL with zero severity
    model_only = [s for s in rep["blind_spots"] if s["type"] == "model_only_phase"]
    assert model_only, "post-exploitation phases should appear as intentional blind spots"
    for s in model_only:
        assert s["intentional"] is True and s["severity"] == 0.0


# ── opportunity graph ────────────────────────────────────────────────────────────
def test_graph_structure(cold):
    g = OpportunityGraph(cold).build()
    assert g["capability_nodes"] == CAPS
    assert g["finding_type_nodes"] >= 1
    for e in g["addresses_edges"]:
        assert set(e) == {"capability", "finding_type"}
    for b in g["bottleneck_finding_types"]:
        assert b["provider_count"] <= 1                     # fragile single-provider coverage
    for h in g["hub_capabilities"]:
        assert 0.0 <= h["leverage"] <= 1.0


# ── ranker (versioned OpportunityScore) ──────────────────────────────────────────
def test_ranker_bounded_ordered_explainable(cold):
    r = OpportunityRanker(cold)
    rows = r.rank()
    assert len(rows) == CAPS
    scores = [o.score for o in rows]
    assert scores == sorted(scores, reverse=True)            # ranked desc
    for o in rows:
        assert 0.0 <= o.score <= 1.0
        assert 0.0 <= o.coverage_deficit <= 1.0
        assert set(o.components) == {"value", "coverage_deficit", "chain_potential",
                                     "uniqueness", "novelty", "temporal_bonus", "federation_bonus"}
        # the explainable components reconstruct the score (within independent-rounding tolerance,
        # unless the raw blend was clamped into [0,1])
        comp_sum = round(sum(o.components.values()), 4)
        assert abs(o.score - comp_sum) <= 0.001 or o.score in (0.0, 1.0)
        assert o.rationale
    d = rows[0].to_dict()
    assert d["scoring_version"] == OPPORTUNITY_SCORING_VERSION and d["advisory"] is True


def test_ranker_single_and_unknown(cold):
    r = OpportunityRanker(cold)
    cid = r.rank()[0].opportunity_id
    assert r.get(cid).opportunity_id == cid
    assert r.get("nope_cap_123") is None


def test_ranker_by_category(cold):
    rows = OpportunityRanker(cold).by_category()
    assert len(rows) >= 1
    for c in rows:
        assert 0.0 <= c["mean_score"] <= 1.0 and 0.0 <= c["max_score"] <= 1.0


# ── advisor (safe verbs only) ────────────────────────────────────────────────────
def test_advisor_bounded_and_safe(cold):
    recs = OpportunityAdvisor(cold).recommendations(limit=8)
    assert len(recs) <= 8
    blob = json.dumps(recs).lower()
    for verb in ("execute", "exploit", "attack", "deploy", " run "):
        assert verb not in blob
    for rec in recs:
        assert rec["type"] in SAFE_VERBS
        assert rec["advisory"] is True
        assert 0.0 <= rec["confidence"] <= 1.0


# ── health & summary ─────────────────────────────────────────────────────────────
def test_health_bounded(cold):
    h = OpportunityIntelligence(cold).opportunity_health()
    assert 0.0 <= h["opportunity_health_score"] <= 100.0
    assert h["status"] in ("healthy", "watch", "degrading")
    assert h["data_mode"] == "catalog_only"
    assert 0.0 <= h["overall_coverage_index"] <= 1.0
    assert h["advisory"] is True


def test_summary_shape(cold):
    s = OpportunityIntelligence(cold).opportunity_summary()
    assert s["advisory"] is True
    assert s["scoring_version"] == OPPORTUNITY_SCORING_VERSION
    for k in ("opportunity_health", "surface", "top_opportunities", "coverage",
              "blind_spots", "graph", "recommendations"):
        assert k in s


# ── shared load (P/Q/R/S share ONE OffensiveIntelligence) ────────────────────────
def test_shared_offensive_load(cold):
    assert cold.skill().cc.oi is cold.oi          # Phase-R SkillContext shares it
    assert cold.campaign().cc.oi is cold.oi        # Phase-Q CampaignContext shares it
    assert cold.skill().cc.ctx is cold.ctx         # same load-once OffensiveContext


# ── determinism / invariants ─────────────────────────────────────────────────────
def test_deterministic_rebuild_identical():
    a = OpportunityIntelligence().opportunity_summary(now=4242.0)
    b = OpportunityIntelligence().opportunity_summary(now=4242.0)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_store_free():
    pkg = pathlib.Path(__file__).resolve().parents[2] / "hydra" / "opportunity_intel"
    for p in sorted(pkg.glob("*.py")):
        assert "sqlite3" not in p.read_text(encoding="utf-8"), \
            f"opportunity_intel must be store-free (sqlite3 in {p.name})"


def test_no_execution_or_canonical_imports():
    pkg = pathlib.Path(__file__).resolve().parents[2] / "hydra" / "opportunity_intel"
    exec_forbidden = ["subprocess", "os.system", "popen", "requests.", "urllib.request",
                      "socket.", "exec(", "eval("]
    import_forbidden = ["promotion", "confidence", "wiki_store", "WikiStore", "wiki_writer"]
    for p in sorted(pkg.glob("*.py")):
        lines = p.read_text(encoding="utf-8").splitlines()
        full = "\n".join(lines)
        for token in exec_forbidden:
            assert token not in full, f"forbidden '{token}' in opportunity_intel/{p.name}"
        for line in lines:
            s = line.strip()
            if s.startswith(("import ", "from ")):
                for token in import_forbidden:
                    assert token not in line, \
                        f"forbidden import '{token}' in opportunity_intel/{p.name}: {s}"


def test_promotion_confidence_untouched():
    assert confidence_mod.score_from_sources(["a", "b"], {"a": 0.7, "b": 0.7}).value == "high"
    assert hasattr(promotion_mod, "apply_promotion")
