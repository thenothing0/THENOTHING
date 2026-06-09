"""
Phase P — Offensive Capability Intelligence tests.

Deterministic and cold-start safe: the derived logs are pointed at non-existent paths to force the
catalog-only path (stable, known values), plus one seeded test exercising the learned path. Asserts
the invariants: advisory-only, NON-executing, deterministic / rebuild-identical, bounded chains.
"""

import json
import os
import pathlib
import sqlite3

import pytest

import hydra.knowledge.confidence as confidence_mod
import hydra.knowledge.promotion as promotion_mod
from hydra.offensive_intel import (
    AttackChainIntelligence,
    CapabilityEffectivenessEngine,
    OffensiveAdvisor,
    OffensiveContext,
    OffensiveCoverageAnalyzer,
    OffensiveGapAnalyzer,
    OffensiveIntelligence,
    OverlapAnalyzer,
    SkillIntelligence,
)


@pytest.fixture
def cold(tmp_path, monkeypatch):
    """Force cold-start: point the derived logs at non-existent files (catalog-only)."""
    monkeypatch.setenv("HYDRA_TOOL_HEALTH_DB", str(tmp_path / "nope_th.db"))
    monkeypatch.setenv("HYDRA_VERIFICATION_DB", str(tmp_path / "nope_vr.db"))
    return OffensiveContext().load()


def _seed_health(db_path, cap="xss_probing", n=12, outcome="success"):
    from hydra.adapters.tool_health import ToolHealthStore
    os.environ["HYDRA_TOOL_HEALTH_DB"] = str(db_path)
    ToolHealthStore()  # create the schema
    con = sqlite3.connect(str(db_path))
    for i in range(n):
        con.execute(
            "INSERT OR IGNORE INTO health_events(adapter_id,capability_id,category,"
            "event_type,outcome,runtime_ms,dedup_key,occurred_at) VALUES (?,?,?,?,?,?,?,?)",
            (f"{cap}::t", cap, "web", "execution", outcome, 1.0, f"{cap}{i}", 1000.0 + i))
    con.commit()
    con.close()


def test_context_cold_start(cold):
    assert cold.total_events() == 0
    assert cold.catalog().count() == 153
    assert len(cold.skills()) >= 1
    assert cold.now() == 0.0


def test_effectiveness_prior_only_cold_start(cold):
    ranked = CapabilityEffectivenessEngine(cold).rank()
    assert len(ranked) == 153
    assert all(e.status == "prior_only" for e in ranked)
    effs = [e.effectiveness for e in ranked]
    assert effs == sorted(effs, reverse=True)            # descending
    assert all(0.0 <= e.effectiveness <= 1.0 for e in ranked)
    assert all(0.0 <= e.uniqueness <= 1.0 for e in ranked)


def test_effectiveness_is_explainable(cold):
    d = CapabilityEffectivenessEngine(cold).get("http_probing").to_dict()
    for k in ("effectiveness", "utility", "contribution", "uniqueness",
              "redundancy", "samples", "status", "rationale", "advisory"):
        assert k in d
    assert d["advisory"] is True
    assert "prior=" in d["rationale"]


def test_learned_path_moves_off_prior(tmp_path, monkeypatch):
    db = tmp_path / "th.db"
    monkeypatch.setenv("HYDRA_VERIFICATION_DB", str(tmp_path / "nope_vr.db"))
    _seed_health(db, cap="xss_probing", n=12, outcome="success")
    e = CapabilityEffectivenessEngine(OffensiveContext().load()).get("xss_probing")
    assert e.status == "learned"
    assert e.samples >= 10
    assert e.effectiveness > 0.5            # moved above the 0.5 prior toward observed success


def test_chains_bounded_and_advisory(cold):
    out = AttackChainIntelligence(cold).chains(limit=5)
    assert out["advisory"] is True
    assert len(out["chains"]) <= 5
    assert out["total_chains"] <= 200
    for c in out["chains"]:
        assert 2 <= c["length"] <= out["bounds"]["max_depth"]
        assert 0.0 <= c["effectiveness"] <= 1.0
        assert 0.0 <= c["diversity"] <= 1.0


def test_chains_respect_requires_ordering(cold):
    chains = AttackChainIntelligence(cold).chains(limit=100000)["chains"]
    pairs = [c["chain"] for c in chains
             if "parameter_discovery" in c["chain"] and "xss_probing" in c["chain"]]
    for ch in pairs:
        assert ch.index("parameter_discovery") < ch.index("xss_probing")


def test_overlap_pairs_canonical(cold):
    pairs = OverlapAnalyzer(cold).redundant_pairs(threshold=0.7, limit=10)
    assert len(pairs) <= 10
    for p in pairs:
        assert p["capability_a"] < p["capability_b"]
        assert 0.7 <= p["overlap"] <= 1.0
        assert p["lower_value"] in (p["capability_a"], p["capability_b"])


def test_coverage_totals(cold):
    cov = OffensiveCoverageAnalyzer(cold).report()
    assert cov["advisory"] is True
    assert sum(c["capabilities"] for c in cov["category_coverage"]) == 153
    assert cov["workflow_coverage"]["total_capabilities"] == 153


def test_gaps_structure(cold):
    rep = OffensiveGapAnalyzer(cold).report()
    for k in ("weak_categories", "missing_finding_types", "weak_chains", "advisory"):
        assert k in rep


def test_skills_bridge(cold):
    rep = SkillIntelligence(cold).report()
    assert rep["skill_count"] >= 1
    assert rep["bridged_skills"] + rep["unbridged_skills"] == rep["skill_count"]
    for s in rep["skills"]:
        assert s["advisory"] is True


def test_advisor_bounded_and_safe(cold):
    recs = OffensiveAdvisor(cold).recommendations(limit=7)
    assert len(recs) <= 7
    safe = {"strengthen_category", "reduce_redundancy", "diversify_workflow", "exercise_capability"}
    for r in recs:
        assert r["type"] in safe          # never exploit/run/validate/confirm/promote
        assert r["advisory"] is True


def test_health_bounded(cold):
    h = OffensiveIntelligence(cold).offensive_health()
    assert 0.0 <= h["offensive_health_score"] <= 100.0
    assert h["status"] in ("healthy", "watch", "degrading")
    assert h["data_mode"] == "catalog_only"
    assert h["advisory"] is True


def test_summary_shape_and_advisory(cold):
    s = OffensiveIntelligence(cold).offensive_summary()
    assert s["advisory"] is True
    for k in ("offensive_health", "top_capabilities", "strongest_chains",
              "redundant_pairs", "skill_bridge", "recommendations"):
        assert k in s


def test_unknown_capability(cold):
    out = OffensiveIntelligence(cold).offensive_effectiveness("does_not_exist")
    assert out.get("error") == "unknown capability"


def test_deterministic_rebuild_identical(cold):
    a = OffensiveIntelligence().offensive_summary(now=1234.0)
    b = OffensiveIntelligence().offensive_summary(now=1234.0)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_no_execution_or_canonical_imports():
    """No execution/network primitives anywhere; no canonical-writer imports (docstrings that
    merely *mention* promotion.py/confidence.py to assert they are untouched are allowed)."""
    pkg = pathlib.Path(__file__).resolve().parents[2] / "hydra" / "offensive_intel"
    exec_forbidden = ["subprocess", "os.system", "popen", "requests.", "urllib.request",
                      "socket.", "exec(", "eval("]
    import_forbidden = ["promotion", "confidence", "wiki_store", "WikiStore", "wiki_writer"]
    for p in sorted(pkg.glob("*.py")):
        lines = p.read_text(encoding="utf-8").splitlines()
        full = "\n".join(lines)
        for token in exec_forbidden:
            assert token not in full, f"forbidden '{token}' in offensive_intel/{p.name}"
        for line in lines:
            s = line.strip()
            if s.startswith(("import ", "from ")):
                for token in import_forbidden:
                    assert token not in line, (
                        f"forbidden import '{token}' in offensive_intel/{p.name}: {s}")


def test_promotion_confidence_untouched():
    # the protected core must behave exactly as before (no Phase-P side effects)
    assert confidence_mod.score_from_sources(["a", "b"], {"a": 0.7, "b": 0.7}).value == "high"
    assert hasattr(promotion_mod, "apply_promotion")
