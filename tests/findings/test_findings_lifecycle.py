"""Findings lifecycle: state machine, evidence-gated confirm, CVSS, dedup."""

import pytest

from hydra.findings import (
    EvidenceGateError,
    FindingsStore,
    FindingState,
    TransitionError,
    severity_for_cvss,
)


def _store(tmp_path):
    return FindingsStore(db_path=str(tmp_path / "f.db"))


def test_create_and_get(tmp_path):
    s = _store(tmp_path)
    fid = s.create("eng1", "IDOR on orders", vuln_class="idor", endpoint="/api/orders/1043")
    f = s.get(fid)
    assert f["state"] == FindingState.DRAFT and f["vuln_class"] == "idor"


def test_dedup_same_root_cause(tmp_path):
    s = _store(tmp_path)
    a = s.create("eng1", "IDOR", vuln_class="idor", endpoint="/api/orders/1043")
    b = s.create("eng1", "IDOR again", vuln_class="idor", endpoint="/api/orders/9")  # numeric collapse
    assert a == b  # same (vuln_class, normalized endpoint) -> one finding


def test_illegal_transition_blocked(tmp_path):
    s = _store(tmp_path)
    fid = s.create("eng1", "x", vuln_class="xss", endpoint="/a")
    with pytest.raises(TransitionError):
        s.transition(fid, FindingState.CONFIRMED)  # can't skip validated


def test_confirm_requires_request_and_response_evidence(tmp_path):
    s = _store(tmp_path)
    fid = s.create("eng1", "x", vuln_class="idor", endpoint="/a")
    s.transition(fid, FindingState.VALIDATED)
    with pytest.raises(EvidenceGateError):
        s.transition(fid, FindingState.CONFIRMED)  # no evidence yet
    s.add_evidence(fid, "request", "GET /a HTTP/1.1")
    with pytest.raises(EvidenceGateError):
        s.transition(fid, FindingState.CONFIRMED)  # response still missing
    s.add_evidence(fid, "response", "HTTP/1.1 200 OK\n{...}")
    assert s.transition(fid, FindingState.CONFIRMED)["to"] == FindingState.CONFIRMED


def test_full_happy_path_to_remediated(tmp_path):
    s = _store(tmp_path)
    fid = s.create("eng1", "x", vuln_class="idor", endpoint="/a")
    s.transition(fid, FindingState.VALIDATED)
    s.add_evidence(fid, "request", "req")
    s.add_evidence(fid, "response", "resp")
    s.transition(fid, FindingState.CONFIRMED)
    s.transition(fid, FindingState.REPORTED)
    assert s.transition(fid, FindingState.REMEDIATED)["to"] == FindingState.REMEDIATED


def test_cvss_scoring_sets_severity():
    assert severity_for_cvss(0) == "info"
    assert severity_for_cvss(3.9) == "low"
    assert severity_for_cvss(7.5) == "high"
    assert severity_for_cvss(9.8) == "critical"


def test_evidence_content_is_redacted(tmp_path):
    s = _store(tmp_path)
    fid = s.create("eng1", "x", vuln_class="auth", endpoint="/a")
    s.add_evidence(fid, "request", "curl https://admin:Sup3rSecret@app/a")
    with s._conn() as c:
        row = c.execute("SELECT content FROM evidence WHERE finding_id=?", (fid,)).fetchone()
    assert "Sup3rSecret" not in row["content"]
