"""Coverage engine: matrix upsert, scores, and the /next prioritization."""

from hydra.coverage import CoverageStore


def _store(tmp_path):
    return CoverageStore(db_path=str(tmp_path / "c.db"))


def test_record_upsert_and_matrix(tmp_path):
    s = _store(tmp_path)
    r1 = s.record("eng1", "/api/orders", "idor", parameter="id")
    assert r1["updated"] is False and r1["status"] == "untested"
    r2 = s.record("eng1", "/api/orders", "idor", parameter="id", status="passed")
    assert r2["updated"] is True and r2["status"] == "passed"
    assert len(s.matrix("eng1")) == 1  # same tuple = upsert, not a new row


def test_scores(tmp_path):
    s = _store(tmp_path)
    s.record("eng1", "/api/orders", "idor", parameter="id", auth_area="user", status="passed")
    s.record("eng1", "/api/orders", "sqli", parameter="id", status="untested")
    s.record("eng1", "/login", "auth_bypass", auth_area="auth", status="untested")
    summ = s.summary("eng1", open_finding_severities=["high"])
    assert summ["total_tuples"] == 3 and summ["tested_tuples"] == 1
    assert 0 < summ["coverage_score"] < 1
    assert summ["attack_surface_score"] > 0
    assert summ["risk_score"] > 7  # one 'high' open finding (7.0) + uncovered high-value classes


def test_next_prefers_autharea_high_value(tmp_path):
    s = _store(tmp_path)
    s.record("eng1", "/static", "xss", status="untested")                    # low value
    s.record("eng1", "/account", "idor", auth_area="user", status="untested")  # high value + auth
    nxt = s.next("eng1", limit=5)
    assert nxt[0]["vuln_class"] == "idor" and nxt[0]["auth_area"] == "user"
    assert nxt[0]["value"] >= nxt[-1]["value"]


def test_passed_tuple_not_in_next(tmp_path):
    s = _store(tmp_path)
    s.record("eng1", "/a", "idor", status="passed")
    assert s.next("eng1") == []
