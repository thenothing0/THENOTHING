"""Phase D.1 — learning hardening tests for F-D1..F-D5."""

import sqlite3
import threading

from hydra.capabilities.source_learning import (
    EV_CONFIRMED,
    EV_DISCOVERY,
    SourceLearningStore,
)
from hydra.knowledge.discovery import PatternDiscovery
from hydra.knowledge.opportunity import OpportunityScorer, record_outcome
from hydra.knowledge.schema import NodeType
from hydra.knowledge.wiki_store import WikiStore


def _seed(tmp_path, sources=("source.subfinder",)):
    ws = WikiStore(tmp_path / "wiki")
    ws.upsert(NodeType.TARGET, "acme", {"tags": ["t"]}, "# acme\n")
    for s, st in (("a", "submitted"), ("b", "confirmed")):
        ws.upsert(NodeType.FINDING, f"idor-{s}",
                  {"tags": ["idor", "api"], "status": st, "target": "[[acme]]",
                   "sources": list(sources)}, f"# {s}\nidor escalation\n")
    return ws


# ── F-D1: idempotent outcome attribution ──────────────────────────────────────
def test_reconfirm_credits_once(tmp_path):
    ws = _seed(tmp_path)
    learn = SourceLearningStore(tmp_path / "l.db")
    cid = next(c for c in PatternDiscovery(ws).discover() if c.signature == "idor").id
    results = [record_outcome("pattern", cid, "confirmed", ws, learn) for _ in range(10)]
    sc = learn.scores("source.subfinder")
    assert sc.confirmed_findings == 1 and sc.unique_patterns_created == 1
    assert results[0]["recorded"] is True
    assert all(r["idempotent_skip"] for r in results[1:])


def test_rereject_penalizes_once(tmp_path):
    ws = _seed(tmp_path)
    learn = SourceLearningStore(tmp_path / "l.db")
    cid = next(c for c in PatternDiscovery(ws).discover() if c.signature == "idor").id
    for _ in range(10):
        record_outcome("pattern", cid, "rejected", ws, learn)
    assert learn.scores("source.subfinder").rejected_candidates == 1


def test_idempotent_replay_identical_scores(tmp_path):
    ws = _seed(tmp_path)
    cid = next(c for c in PatternDiscovery(ws).discover() if c.signature == "idor").id

    def run(db):
        learn = SourceLearningStore(db)
        for _ in range(5):
            record_outcome("pattern", cid, "confirmed", ws, learn)
        return [s.to_dict() | {"last_success_at": None} for s in learn.all_scores()]

    assert run(tmp_path / "a.db") == run(tmp_path / "b.db")


def test_concurrent_confirm_same_candidate_credits_once(tmp_path):
    ws = _seed(tmp_path)
    db = tmp_path / "l.db"
    SourceLearningStore(db)
    cid = next(c for c in PatternDiscovery(ws).discover() if c.signature == "idor").id

    def worker():
        record_outcome("pattern", cid, "confirmed", ws, SourceLearningStore(db))

    ts = [threading.Thread(target=worker) for _ in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert SourceLearningStore(db).scores("source.subfinder").confirmed_findings == 1


# ── F-D2: effectiveness no dead-zone ──────────────────────────────────────────
def test_effectiveness_no_dead_zone(tmp_path):
    s = SourceLearningStore(tmp_path / "l.db")
    for _ in range(10):
        s.record_source_event("source.x", EV_CONFIRMED)
    sc = s.scores("source.x")
    assert sc.discoveries == 0 and sc.effectiveness_score == 1.0  # was 0.0 before fix


def test_effectiveness_bounded_and_consistent(tmp_path):
    s = SourceLearningStore(tmp_path / "l.db")
    for _ in range(8):
        s.record_source_event("source.y", EV_DISCOVERY)
    for _ in range(6):
        s.record_source_event("source.y", EV_CONFIRMED)
    sc = s.scores("source.y")
    assert sc.effectiveness_score == round(6 / 8, 4)   # discoveries dominate denom → unchanged
    assert 0.0 <= sc.effectiveness_score <= 1.0


# ── F-D3: exploration + decay (ranking-only, deterministic) ───────────────────
def test_exploration_lets_underexplored_surface(tmp_path):
    # two equal-confidence candidates: one backed by an entrenched source, one by a
    # fresh source. Exploration must give the fresh-source candidate a higher score.
    ws = WikiStore(tmp_path / "wiki")
    ws.upsert(NodeType.TARGET, "acme", {"tags": ["t"]}, "# acme\n")
    for v, src in (("idor", "source.entrenched"), ("ssrf", "source.fresh")):
        for s, st in (("a", "submitted"), ("b", "confirmed")):
            ws.upsert(NodeType.FINDING, f"{v}-{s}",
                      {"tags": [v, "api"], "status": st, "target": "[[acme]]", "sources": [src]},
                      f"# {s}\n{v} escalation\n")
    learn = SourceLearningStore(tmp_path / "l.db")
    for _ in range(200):  # entrenched source: lots of history
        learn.record_source_event("source.entrenched", EV_DISCOVERY)
    learn.record_source_event("source.fresh", EV_DISCOVERY)  # barely explored
    scorer = OpportunityScorer(ws, learn, now=1_000_000.0)
    by_sig = {tuple(o.source_ids): o for o in scorer.rank()}
    entrenched = by_sig[("source.entrenched",)]
    fresh = by_sig[("source.fresh",)]
    assert fresh.components["exploration"] > entrenched.components["exploration"]


def test_decay_changes_ranking_over_time(tmp_path):
    import time
    ws = _seed(tmp_path, sources=("source.s",))
    learn = SourceLearningStore(tmp_path / "l.db")
    learn.record_source_event("source.s", EV_DISCOVERY)
    learn.record_source_event("source.s", EV_CONFIRMED)  # last_success ~ now
    cand = next(c for c in PatternDiscovery(ws).discover() if c.signature == "idor")
    t0 = time.time()                          # anchor "fresh" at the recording time
    fresh = OpportunityScorer(ws, learn, now=t0).score(cand)
    stale = OpportunityScorer(ws, learn, now=t0 + 365 * 24 * 3600).score(cand)  # +1 year
    assert fresh.components["effectiveness"] > 0.0
    assert stale.components["effectiveness"] < fresh.components["effectiveness"]


def test_ranking_deterministic_for_fixed_now(tmp_path):
    ws = _seed(tmp_path, sources=("source.s",))
    learn = SourceLearningStore(tmp_path / "l.db")
    learn.record_source_event("source.s", EV_CONFIRMED)
    a = OpportunityScorer(ws, learn, now=1234.0).rank()
    b = OpportunityScorer(ws, learn, now=1234.0).rank()
    assert [(o.candidate_id, o.score) for o in a] == [(o.candidate_id, o.score) for o in b]


# ── F-D5: WAL + concurrency ───────────────────────────────────────────────────
def test_wal_mode_enabled(tmp_path):
    db = tmp_path / "l.db"
    SourceLearningStore(db)
    assert sqlite3.connect(str(db)).execute("PRAGMA journal_mode").fetchone()[0] == "wal"


def test_concurrent_writers_and_readers_no_lock_failure(tmp_path):
    db = tmp_path / "l.db"
    SourceLearningStore(db)
    errors = []

    def writer(w):
        s = SourceLearningStore(db)
        for i in range(50):
            try:
                s.record_source_event(f"source.w{w}", EV_DISCOVERY)
            except Exception as e:  # pragma: no cover
                errors.append(str(e))

    def reader():
        s = SourceLearningStore(db)
        for _ in range(50):
            try:
                s.all_scores()
            except Exception as e:  # pragma: no cover
                errors.append(str(e))

    threads = [threading.Thread(target=writer, args=(w,)) for w in range(6)]
    threads += [threading.Thread(target=reader) for _ in range(3)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert errors == []
    assert sum(s.discoveries for s in SourceLearningStore(db).all_scores()) == 300


# ── F-D4: single-query all_scores identical to per-source ─────────────────────
def test_all_scores_matches_per_source(tmp_path):
    s = SourceLearningStore(tmp_path / "l.db")
    for i in range(60):
        s.record_source_event(f"source.s{i % 5}", EV_DISCOVERY if i % 2 else EV_CONFIRMED)
    grouped = {x.source_id: x.to_dict() for x in s.all_scores()}
    per = {sid: s.scores(sid).to_dict() for sid in grouped}
    # exclude wall-clock last_success_at (same value, but compare the derived scores)
    for d in list(grouped.values()) + list(per.values()):
        d.pop("last_success_at")
    assert grouped == per
