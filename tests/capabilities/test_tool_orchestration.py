"""Phase G — capability catalog v2, ToolSelector, CapabilityCoverage."""

import time

import pytest

from hydra.capabilities.capability_catalog import CATEGORIES, CapabilityCatalog
from hydra.capabilities.source_learning import (
    EV_CONFIRMED,
    EV_DISCOVERY,
    SourceLearningStore,
)
from hydra.capabilities.tool_selection import CapabilityCoverage, ToolSelector
from hydra.knowledge.verification import VerificationLearningStore


# ── catalog v2 ────────────────────────────────────────────────────────────────
def test_catalog_has_75_plus_capabilities_across_9_categories():
    cat = CapabilityCatalog().load()
    assert cat.count() >= 75
    assert set(cat.categories()) == set(CATEGORIES)
    counts = cat.category_counts()
    assert all(counts.get(c, 0) > 0 for c in CATEGORIES)


def test_catalog_entries_well_formed():
    cat = CapabilityCatalog().load()
    for e in cat.all():
        assert e.capability_id and e.category in CATEGORIES
        assert e.tools                      # every capability maps to >=1 tool
        assert 0.0 <= e.confidence_weight <= 1.0
        assert isinstance(e.offline_runnable, bool)
        assert isinstance(e.verification_coverage, int)


def test_catalog_queries():
    cat = CapabilityCatalog().load()
    assert {e.capability_id for e in cat.by_target_type("apk")}  # mobile caps
    assert any(e.is_verification for e in cat.by_category("verification"))
    assert "subfinder" in cat.get("subdomain_discovery").tools


# ── ToolSelector: learning-driven, deterministic ──────────────────────────────
def _stores(tmp_path):
    return (CapabilityCatalog().load(),
            SourceLearningStore(tmp_path / "l.db"),
            VerificationLearningStore(tmp_path / "v.db"))


def test_proven_tool_ranks_first(tmp_path):
    cat, learn, ver = _stores(tmp_path)
    t0 = time.time()
    for _ in range(20):
        learn.record_source_event("source.subfinder", EV_DISCOVERY)
    for _ in range(15):
        learn.record_source_event("source.subfinder", EV_CONFIRMED)
    ranked = ToolSelector(cat, learn, ver, now=t0).rank("subdomain_discovery")
    assert ranked[0].tool == "subfinder"


def test_selection_deterministic(tmp_path):
    cat, learn, ver = _stores(tmp_path)
    a = ToolSelector(cat, learn, ver, now=1000.0).rank("subdomain_discovery")
    b = ToolSelector(cat, learn, ver, now=1000.0).rank("subdomain_discovery")
    assert [(t.tool, t.score) for t in a] == [(t.tool, t.score) for t in b]


def test_verification_effectiveness_influences_ranking(tmp_path):
    cat, learn, ver = _stores(tmp_path)
    for _ in range(9):
        ver.record_verification("idor", "idor_verifier", "success")
    ver.record_verification("idor", "idor_verifier", "failure")
    best = ToolSelector(cat, learn, ver, now=time.time()).select("idor_verification")
    assert best.tool == "idor_verifier"
    assert best.components["verification"] > 0.5


def test_rank_unknown_capability_raises(tmp_path):
    cat, learn, ver = _stores(tmp_path)
    with pytest.raises(KeyError):
        ToolSelector(cat, learn, ver).rank("nope")


def test_selection_rebuildable_identical(tmp_path):
    cat = CapabilityCatalog().load()
    seq = [("source.subfinder", EV_DISCOVERY)] * 4 + [("source.subfinder", EV_CONFIRMED)] * 3

    def run(tag):
        learn = SourceLearningStore(tmp_path / f"l{tag}.db")
        ver = VerificationLearningStore(tmp_path / f"v{tag}.db")
        for sid, ev in seq:
            learn.record_source_event(sid, ev)
        return [(t.tool, t.score) for t in ToolSelector(cat, learn, ver, now=1000.0).rank("subdomain_discovery")]

    assert run("a") == run("b")


# ── CapabilityCoverage ────────────────────────────────────────────────────────
def test_coverage_report(tmp_path):
    cat, learn, ver = _stores(tmp_path)
    for _ in range(30):
        learn.record_source_event("source.subfinder", EV_DISCOVERY)
    rep = CapabilityCoverage(cat, learn, ver).report()
    assert rep["total_capabilities"] >= 75
    # subdomain_discovery is now covered (subfinder has events); most others are not
    assert "subdomain_discovery" not in rep["uncovered_capabilities"]
    assert rep["uncovered_count"] >= 1
    assert rep["overused_tools"][0]["tool"] == "subfinder"
    assert "amass" in rep["underexplored_tools"]
    assert rep["weak_capability_areas"][0]["mean_events"] <= rep["weak_capability_areas"][-1]["mean_events"]


def test_coverage_all_uncovered_when_no_learning(tmp_path):
    cat, learn, ver = _stores(tmp_path)
    rep = CapabilityCoverage(cat, learn, ver).report()
    assert rep["uncovered_count"] == rep["total_capabilities"]
    assert rep["overused_tools"] == []
