"""
Phase R — Skill Composition & Skill Graph Intelligence tests.

Deterministic, store-free, NON-executing. Asserts the derived skill graph (dependency +
composition), bundles, effectiveness, coverage, gaps, marketplace, bounded/safe advisor,
rebuild-identical determinism, that the legacy `hydra.skills` subsystem is not imported, and the
protected-core invariants.
"""

import json
import pathlib

import pytest

import hydra.knowledge.confidence as confidence_mod
import hydra.knowledge.promotion as promotion_mod
from hydra.skill_intel import (
    SkillAdvisor,
    SkillBundles,
    SkillComposition,
    SkillContext,
    SkillCoverageAnalyzer,
    SkillDependencyAnalyzer,
    SkillEffectivenessAnalyzer,
    SkillGapAnalyzer,
    SkillGraph,
    SkillGraphIntelligence,
    SkillMarketplace,
)


@pytest.fixture
def cold(tmp_path, monkeypatch):
    monkeypatch.setenv("HYDRA_TOOL_HEALTH_DB", str(tmp_path / "nope_th.db"))
    monkeypatch.setenv("HYDRA_VERIFICATION_DB", str(tmp_path / "nope_vr.db"))
    return SkillContext()


def test_graph_nodes_are_skills(cold):
    g = SkillGraph(cold).build()
    assert g["node_count"] == len(cold.skills_by_id()) >= 1
    assert g["advisory"] is True


def test_dependency_edges_derived_from_capability_graph(cold):
    g = SkillGraph(cold).build()
    nodes = set(g["nodes"])
    for e in g["dependency_edges"]:
        assert e["from"] in nodes and e["to"] in nodes
        assert e["relation"] in ("requires", "enhances")
        assert e["from"] != e["to"]


def test_composition_edges_shared_capability(cold):
    g = SkillGraph(cold).build()
    nodes = set(g["nodes"])
    for e in g["composition_edges"]:
        assert e["from"] in nodes and e["to"] in nodes
        assert e["relation"] == "shared_capability"


def test_dependencies_report_fields(cold):
    rep = SkillDependencyAnalyzer(cold).report()
    for k in ("dependency_edges", "critical_skills", "isolated_skills",
              "cycles", "acyclic", "advisory"):
        assert k in rep


def test_composition_clusters_partition(cold):
    rep = SkillComposition(cold).report()
    assert rep["cluster_count"] >= 1
    allsk = [s for c in rep["composition_clusters"] for s in c["skills"]]
    assert len(allsk) == len(set(allsk))            # each skill in exactly one cluster


def test_bundles_by_category(cold):
    rep = SkillBundles(cold).report()
    assert rep["bundle_count"] >= 1
    for b in rep["bundles"]:
        assert b["bundle_id"].startswith("bundle_")
        assert b["skill_count"] == len(b["skills"])
        assert b["advisory"] is True


def test_effectiveness_ranked(cold):
    rows = SkillEffectivenessAnalyzer(cold).rank()
    assert len(rows) >= 1
    for r in rows:
        assert 0.0 <= r["uniqueness"] <= 1.0
        assert 0.0 <= r["redundancy"] <= 1.0
    effs = [(r["effectiveness"] or 0.0) for r in rows]
    assert effs == sorted(effs, reverse=True)


def test_effectiveness_single_and_unknown(cold):
    e = SkillEffectivenessAnalyzer(cold)
    sid = e.rank()[0]["skill_id"]
    assert e.get(sid)["skill_id"] == sid
    assert e.get("nope_skill") is None


def test_coverage_totals(cold):
    cov = SkillCoverageAnalyzer(cold).report()
    cc = cov["capability_coverage"]
    assert cc["covered_by_skill"] + cc["uncovered"] == cc["total_capabilities"] == 153
    assert len(cov["category_coverage"]) >= 1
    assert all(0.0 <= c["coverage_pct"] <= 100.0 for c in cov["category_coverage"])


def test_gaps_partition(cold):
    rep = SkillGapAnalyzer(cold).report()
    for k in ("uncovered_capabilities", "weak_skills", "broken_chain_to", "advisory"):
        assert k in rep
    covered = SkillCoverageAnalyzer(cold).capability_coverage()["covered_by_skill"]
    assert rep["uncovered_count"] + covered == 153


def test_marketplace_advisory(cold):
    rep = SkillMarketplace(cold).report()
    assert rep["advisory"] is True
    for r in rep["recommendations"]:
        assert r["type"] in ("add_skills_for_category", "strengthen_skill")
        assert r["advisory"] is True


def test_advisor_bounded_and_safe(cold):
    recs = SkillAdvisor(cold).recommendations(limit=7)
    assert len(recs) <= 7
    safe = {"add_skills_for_category", "strengthen_skill", "cover_capabilities"}
    for r in recs:
        assert r["type"] in safe          # never execute/run/register/promote
        assert r["advisory"] is True


def test_health_bounded(cold):
    h = SkillGraphIntelligence(cold).skill_health()
    assert 0.0 <= h["skill_health_score"] <= 100.0
    assert h["status"] in ("healthy", "watch", "degrading")
    assert h["data_mode"] == "catalog_only"
    assert h["advisory"] is True


def test_summary_shape(cold):
    s = SkillGraphIntelligence(cold).skill_summary()
    assert s["advisory"] is True
    for k in ("skill_health", "graph", "top_skills", "bundles",
              "coverage", "critical_skills", "gaps", "recommendations"):
        assert k in s


def test_deterministic_rebuild_identical(cold):
    a = SkillGraphIntelligence().skill_summary(now=1234.0)
    b = SkillGraphIntelligence().skill_summary(now=1234.0)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_store_free():
    pkg = pathlib.Path(__file__).resolve().parents[2] / "hydra" / "skill_intel"
    for p in sorted(pkg.glob("*.py")):
        assert "sqlite3" not in p.read_text(encoding="utf-8"), \
            f"skill_intel must be store-free (sqlite3 in {p.name})"


def test_does_not_import_legacy_skills_subsystem():
    pkg = pathlib.Path(__file__).resolve().parents[2] / "hydra" / "skill_intel"
    for p in sorted(pkg.glob("*.py")):
        for line in p.read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if s.startswith(("import ", "from ")):
                assert "hydra.skills " not in (line + " ") and "hydra.skills." not in line, \
                    f"skill_intel must not import the legacy hydra.skills subsystem ({p.name}: {s})"


def test_no_execution_or_canonical_imports():
    pkg = pathlib.Path(__file__).resolve().parents[2] / "hydra" / "skill_intel"
    exec_forbidden = ["subprocess", "os.system", "popen", "requests.", "urllib.request",
                      "socket.", "exec(", "eval("]
    import_forbidden = ["promotion", "confidence", "wiki_store", "WikiStore", "wiki_writer"]
    for p in sorted(pkg.glob("*.py")):
        lines = p.read_text(encoding="utf-8").splitlines()
        full = "\n".join(lines)
        for token in exec_forbidden:
            assert token not in full, f"forbidden '{token}' in skill_intel/{p.name}"
        for line in lines:
            s = line.strip()
            if s.startswith(("import ", "from ")):
                for token in import_forbidden:
                    assert token not in line, f"forbidden import '{token}' in skill_intel/{p.name}: {s}"


def test_promotion_confidence_untouched():
    assert confidence_mod.score_from_sources(["a", "b"], {"a": 0.7, "b": 0.7}).value == "high"
    assert hasattr(promotion_mod, "apply_promotion")
