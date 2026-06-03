"""Phase D — SourceLearningStore: scores evolve, rebuildable-identical, deterministic."""

import pytest

from hydra.capabilities.source_learning import (
    EV_CHAIN,
    EV_CONFIRMED,
    EV_DISCOVERY,
    EV_DUPLICATE,
    EV_PATTERN,
    EV_REJECTED,
    SourceLearningStore,
)


def _store(tmp_path):
    return SourceLearningStore(tmp_path / "learn.db")


def test_scores_evolve_with_events(tmp_path):
    s = _store(tmp_path)
    base = s.scores("source.fofa")
    assert base.trust_score == 0.5 and base.effectiveness_score == 0.0
    for _ in range(8):
        s.record_source_event("source.fofa", EV_DISCOVERY)
    for _ in range(6):
        s.record_source_event("source.fofa", EV_CONFIRMED)
    s.record_source_event("source.fofa", EV_REJECTED)
    sc = s.scores("source.fofa")
    assert sc.discoveries == 8 and sc.confirmed_findings == 6 and sc.rejected_candidates == 1
    assert sc.effectiveness_score == round(6 / 8, 4)        # yield
    assert sc.trust_score == round(7 / 9, 4)                # (6+1)/(6+1+2)
    assert sc.trust_score > base.trust_score                # improved with confirms


def test_negative_feedback_lowers_trust(tmp_path):
    s = _store(tmp_path)
    s.record_source_event("source.x", EV_CONFIRMED)
    high = s.scores("source.x").trust_score
    for _ in range(5):
        s.record_source_event("source.x", EV_REJECTED)
    assert s.scores("source.x").trust_score < high


def test_novelty_reflects_new_vs_duplicate(tmp_path):
    s = _store(tmp_path)
    s.record_source_event("source.novel", EV_PATTERN)
    s.record_source_event("source.novel", EV_CHAIN)
    s.record_source_event("source.dupey", EV_DUPLICATE)
    s.record_source_event("source.dupey", EV_DUPLICATE)
    assert s.scores("source.novel").novelty_score > s.scores("source.dupey").novelty_score


def _score_view(store):
    """Derived scores + counts, excluding the wall-clock last_success_at timestamp."""
    out = []
    for x in store.all_scores():
        d = x.to_dict()
        d.pop("last_success_at")
        out.append(d)
    return out


def test_scores_are_rebuildable_identical(tmp_path):
    """Same event sequence in two stores ⇒ identical derived scores (event-sourced).

    last_success_at is event-recording wall-clock time and is excluded — the *scores*
    (the thing the system reasons with) are reproducible."""
    events = [("source.a", EV_DISCOVERY), ("source.a", EV_DISCOVERY),
              ("source.a", EV_CONFIRMED), ("source.b", EV_DISCOVERY),
              ("source.b", EV_REJECTED), ("source.a", EV_PATTERN)]
    s1 = SourceLearningStore(tmp_path / "a.db")
    s2 = SourceLearningStore(tmp_path / "b.db")
    for sid, ev in events:
        s1.record_source_event(sid, ev)
        s2.record_source_event(sid, ev)
    assert _score_view(s1) == _score_view(s2)


def test_reset_then_replay_reproduces_scores(tmp_path):
    s = _store(tmp_path)
    seq = [("source.a", EV_DISCOVERY), ("source.a", EV_CONFIRMED), ("source.b", EV_REJECTED)]
    for sid, ev in seq:
        s.record_source_event(sid, ev)
    before = _score_view(s)
    s.reset()
    assert s.all_scores() == []
    for sid, ev in seq:
        s.record_source_event(sid, ev)
    assert _score_view(s) == before


def test_keyed_by_stable_source_id_and_requires_it(tmp_path):
    s = _store(tmp_path)
    with pytest.raises(ValueError):
        s.record_source_event("", EV_DISCOVERY)
    s.record_source_event("source.crt_sh", EV_DISCOVERY)
    assert all(x.source_id.startswith("source.") for x in s.all_scores())


def test_prioritization_outcome_breakdowns(tmp_path):
    s = _store(tmp_path)
    s.record_outcome("pattern", "p1", "confirmed", signature="idor", evidence_combo=["validated_finding", "validated_finding"])
    s.record_outcome("pattern", "p2", "confirmed", signature="idor", evidence_combo=["validated_finding", "report_intel"])
    s.record_outcome("pattern", "p3", "rejected", signature="xss", evidence_combo=["report_intel", "report_intel"])
    pats = {d["signature"]: d for d in s.successful_patterns()}
    assert pats["idor"]["confirmed"] == 2 and pats["idor"]["acceptance_rate"] == 1.0
    assert pats["xss"]["acceptance_rate"] == 0.0
    combos = s.accepted_evidence_combos()
    assert combos and combos[0]["acceptance_rate"] >= combos[-1]["acceptance_rate"]  # sorted desc


def test_effective_source_types(tmp_path):
    s = _store(tmp_path)
    s.record_source_event("source.subfinder", EV_DISCOVERY)
    s.record_source_event("source.subfinder", EV_CONFIRMED)
    s.record_source_event("source.crt_sh", EV_DISCOVERY)
    cats = s.effective_source_types({"source.subfinder": "active", "source.crt_sh": "passive"})
    by = {c["category"]: c for c in cats}
    assert by["active"]["yield"] == 1.0 and by["passive"]["yield"] == 0.0
