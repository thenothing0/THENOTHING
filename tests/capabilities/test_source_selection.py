"""Phase E — AdaptiveSourceSelector + ReconPlanner: determinism, exploration, decay, feedback."""

import time

from hydra.capabilities.registry import CapabilityRegistry
from hydra.capabilities.source_learning import (
    EV_CONFIRMED,
    EV_DISCOVERY,
    SourceLearningStore,
)
from hydra.capabilities.source_selection import AdaptiveSourceSelector
from hydra.capabilities.sources import ExecutionPolicy
from hydra.recon_fusion.recon_planner import ReconPlanner


def _reg():
    return CapabilityRegistry().load()


def _learn(tmp_path):
    return SourceLearningStore(tmp_path / "l.db")


# ── selection determinism + offline gating ────────────────────────────────────
def test_selection_deterministic_for_fixed_now(tmp_path):
    reg, learn = _reg(), _learn(tmp_path)
    a = AdaptiveSourceSelector(reg, learn, now=1000.0).select("discover_subdomains")
    b = AdaptiveSourceSelector(reg, learn, now=1000.0).select("discover_subdomains")
    assert [(s.source_id, s.score) for s in a] == [(s.source_id, s.score) for s in b]


def test_selection_marks_runnable_by_policy(tmp_path):
    reg, learn = _reg(), _learn(tmp_path)
    ranked = AdaptiveSourceSelector(reg, learn, now=1000.0).select(
        "discover_subdomains", ExecutionPolicy.offline(), limit=20)
    runnable = {s.source_id for s in ranked if s.runnable}
    assert runnable == {"source.subfinder", "source.amass",
                        "source.assetfinder", "source.findomain"}


def test_unknown_capability_raises(tmp_path):
    import pytest
    with pytest.raises(KeyError):
        AdaptiveSourceSelector(_reg(), _learn(tmp_path)).select("nope")


# ── learning influence: proven source rises ──────────────────────────────────
def test_proven_source_outranks_cold_when_fresh(tmp_path):
    reg, learn = _reg(), _learn(tmp_path)
    t0 = time.time()
    for _ in range(20):
        learn.record_source_event("source.subfinder", EV_DISCOVERY)
    for _ in range(15):
        learn.record_source_event("source.subfinder", EV_CONFIRMED)
    ranked = AdaptiveSourceSelector(reg, learn, now=t0).select("discover_subdomains")
    assert ranked[0].source_id == "source.subfinder"


# ── exploration: under-explored retains a path; decay frees incumbents ────────
def test_decay_lets_exploration_surface_stale_incumbent(tmp_path):
    reg, learn = _reg(), _learn(tmp_path)
    t0 = time.time()
    for _ in range(20):
        learn.record_source_event("source.subfinder", EV_DISCOVERY)
    for _ in range(15):
        learn.record_source_event("source.subfinder", EV_CONFIRMED)
    fresh_top = AdaptiveSourceSelector(reg, learn, now=t0).select("discover_subdomains")[0]
    stale_top = AdaptiveSourceSelector(
        reg, learn, now=t0 + 300 * 24 * 3600).select("discover_subdomains")[0]
    assert fresh_top.source_id == "source.subfinder"
    assert stale_top.source_id != "source.subfinder"  # incumbent yielded after going stale


def test_exploration_component_decreases_with_usage(tmp_path):
    reg, learn = _reg(), _learn(tmp_path)
    for _ in range(100):
        learn.record_source_event("source.subfinder", EV_DISCOVERY)
    sel = AdaptiveSourceSelector(reg, learn, now=time.time())
    by_id = {s.source_id: s for s in sel.select("discover_subdomains", limit=20)}
    assert by_id["source.subfinder"].components["exploration"] < by_id["source.amass"].components["exploration"]


# ── ReconPlanner ──────────────────────────────────────────────────────────────
def test_recon_plan_structure_and_determinism(tmp_path):
    reg, learn = _reg(), _learn(tmp_path)
    p1 = ReconPlanner(reg, learn, now=1000.0).plan("acme.com", "api", prior_findings=2)
    p2 = ReconPlanner(reg, learn, now=1000.0).plan("acme.com", "api", prior_findings=2)
    assert p1.to_dict() == p2.to_dict()                       # deterministic
    assert [s.capability for s in p1.steps][:2] == ["discover_subdomains", "http_probe"]
    assert 0.0 <= p1.expected_value <= 1.0
    assert p1.ranked_sources and p1.emphasis["target_under_covered"] is True


def test_recon_plan_target_type_changes_capabilities(tmp_path):
    reg, learn = _reg(), _learn(tmp_path)
    cloud = ReconPlanner(reg, learn, now=1.0).plan("acme.com", "cloud")
    assert cloud.steps[0].capability == "cloud_asset_discovery"


def test_planner_bounded_limits(tmp_path):
    from hydra.recon_fusion.recon_planner import PlannerLimits
    reg, learn = _reg(), _learn(tmp_path)
    p = ReconPlanner(reg, learn, now=1.0).plan(
        "acme.com", "api", limits=PlannerLimits(max_capabilities=2, sources_per_step=3))
    assert len(p.steps) <= 2
    assert all(len(s.sources) <= 3 for s in p.steps)


# ── learning feedback loop: rebuild-identical selection ───────────────────────
def test_selection_rebuildable_identical(tmp_path):
    reg = _reg()
    seq = [("source.subfinder", EV_DISCOVERY)] * 5 + [("source.subfinder", EV_CONFIRMED)] * 3

    def run(db):
        learn = SourceLearningStore(db)
        for sid, ev in seq:
            learn.record_source_event(sid, ev)
        ranked = AdaptiveSourceSelector(reg, learn, now=1000.0).select("discover_subdomains")
        return [(s.source_id, s.score) for s in ranked]

    assert run(tmp_path / "a.db") == run(tmp_path / "b.db")
