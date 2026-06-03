"""Phase F — verification learning, validation intelligence, playbooks, tool catalog."""

import sqlite3
import threading

import pytest

from hydra.capabilities.tool_capabilities import ToolCapabilityRegistry
from hydra.knowledge.verification import (
    ValidationIntelligence,
    VerificationLearningStore,
    VerificationPlaybookGenerator,
)


def _store(tmp_path):
    return VerificationLearningStore(tmp_path / "v.db")


def _seed(s):
    for _ in range(8):
        s.record_verification("idor", "idor_verifier", "success",
                              evidence_type="auth_swap", evidence_strength=0.9,
                              source_ids=["source.subfinder"])
    for _ in range(2):
        s.record_verification("idor", "idor_verifier", "failure", evidence_type="auth_swap")
    for _ in range(2):
        s.record_verification("idor", "auth_context_swap", "success", evidence_type="session_diff")
    for _ in range(6):
        s.record_verification("idor", "auth_context_swap", "failure", evidence_type="session_diff")


# ── learning correctness + determinism ────────────────────────────────────────
def test_method_stats_ranked_by_success(tmp_path):
    s = _store(tmp_path)
    _seed(s)
    stats = s.method_stats()
    assert stats[0]["method"] == "idor_verifier"
    assert stats[0]["successes"] == 8 and stats[0]["attempts"] == 10
    assert stats[0]["success_rate"] > stats[1]["success_rate"]


def test_rebuild_identical_statistics(tmp_path):
    events = [("idor", "idor_verifier", "success"), ("idor", "idor_verifier", "failure"),
              ("ssrf", "ssrf_verifier", "success")]

    def run(db):
        s = VerificationLearningStore(db)
        for vc, m, o in events:
            s.record_verification(vc, m, o)
        return [s.method_stats(), s.by_vuln_class(), s.by_evidence_type()]

    assert run(tmp_path / "a.db") == run(tmp_path / "b.db")


def test_reset_then_replay_reproduces(tmp_path):
    s = _store(tmp_path)
    _seed(s)
    before = s.method_stats()
    s.reset()
    assert s.method_stats() == []
    _seed(s)
    assert s.method_stats() == before


def test_record_validates_inputs(tmp_path):
    s = _store(tmp_path)
    with pytest.raises(ValueError):
        s.record_verification("", "m", "success")
    with pytest.raises(ValueError):
        s.record_verification("idor", "m", "maybe")


# ── idempotency (replay consistency) ──────────────────────────────────────────
def test_dedup_key_idempotent(tmp_path):
    s = _store(tmp_path)
    n1 = s.record_verification("idor", "idor_verifier", "success", dedup_key="v1")
    n2 = s.record_verification("idor", "idor_verifier", "success", dedup_key="v1")
    assert n1 is True and n2 is False
    assert s.method_stats()[0]["attempts"] == 1


def test_concurrent_dedup_records_once(tmp_path):
    db = tmp_path / "v.db"
    VerificationLearningStore(db)

    def w():
        VerificationLearningStore(db).record_verification("idor", "idor_verifier", "success", dedup_key="k")

    ts = [threading.Thread(target=w) for _ in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert VerificationLearningStore(db).method_stats()[0]["attempts"] == 1


# ── validation intelligence APIs ──────────────────────────────────────────────
def test_validation_intelligence_apis(tmp_path):
    s = _store(tmp_path)
    _seed(s)
    vi = ValidationIntelligence(s)
    assert vi.best_sequence("idor")[0] == "idor_verifier"
    assert vi.what_next("idor", ["idor_verifier"])["method"] == "auth_context_swap"
    ev = vi.most_predictive_evidence()
    assert ev[0]["evidence_type"] == "auth_swap"  # higher success rate
    cats = s.by_source_category({"source.subfinder": "active"})
    assert any(c["category"] == "active" for c in cats)


# ── playbooks (advisory, deterministic) ───────────────────────────────────────
def test_playbook_merges_learned_and_default(tmp_path):
    s = _store(tmp_path)
    _seed(s)
    pb = VerificationPlaybookGenerator(s).generate("idor")
    methods = [st.method for st in pb.steps]
    assert pb.steps[0].method == "idor_verifier"          # learned, best
    assert "object_id_enumeration" in methods             # static default merged in
    assert 0.0 <= pb.expected_verification_value <= 1.0
    assert pb.confidence_of_success > 0.0


def test_playbook_coldstart_uses_defaults(tmp_path):
    pb = VerificationPlaybookGenerator(_store(tmp_path)).generate("ssrf")
    methods = [st.method for st in pb.steps]
    assert "ssrf_verifier" in methods and all(st.source == "default" for st in pb.steps)


def test_playbook_deterministic(tmp_path):
    s = _store(tmp_path)
    _seed(s)
    gen = VerificationPlaybookGenerator(s)
    assert gen.generate("idor").to_dict() == gen.generate("idor").to_dict()


# ── WAL / concurrency ─────────────────────────────────────────────────────────
def test_wal_enabled(tmp_path):
    db = tmp_path / "v.db"
    VerificationLearningStore(db)
    assert sqlite3.connect(str(db)).execute("PRAGMA journal_mode").fetchone()[0] == "wal"


# ── tool capability registry ──────────────────────────────────────────────────
def test_tool_registry_catalog():
    r = ToolCapabilityRegistry().load()
    assert set(r.categories()) == {"recon", "web", "cloud", "verification"}
    assert len(r.all()) >= 20
    assert all(t.id.startswith("tool.") for t in r.all())
    assert {t.name for t in r.by_category("cloud")} >= {"trufflehog", "gitleaks", "prowler"}


def test_tool_registry_finding_type_and_verifiers():
    r = ToolCapabilityRegistry().load()
    assert any(t.name == "idor_verifier" for t in r.by_finding_type("idor"))
    vt = {t.name for t in r.verification_tools()}
    assert {"ssrf_verifier", "oauth_verifier", "idor_verifier"} <= vt


def test_tool_effectiveness_from_verification_store(tmp_path):
    r = ToolCapabilityRegistry().load()
    s = _store(tmp_path)
    for _ in range(9):
        s.record_verification("idor", "idor_verifier", "success")
    s.record_verification("idor", "idor_verifier", "failure")
    eff = r.effectiveness("tool.idor_verifier", s)
    assert eff["attempts"] == 10 and eff["success_rate"] > 0.7
    # registry stores no effectiveness itself — it's read from the derived store
    assert not hasattr(r.get("tool.idor_verifier"), "historical_effectiveness")
