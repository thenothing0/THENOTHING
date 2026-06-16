"""
Attack section improvements — pure-logic tests (network-free, deterministic).

Differential detection (#1), access-control diff (#2), WAF signal (#5), injection-point discovery
(#4), gated chain execution + redaction (#6), report builder + severity elevation (#7), and the
session merge (#2). The live end-to-end paths live in tests/attack_runtime/.
"""

import json


from hydra.attack import (
    AccessControlAnalyzer,
    AttackReporter,
    ChainExecutor,
    DifferentialDetector,
    InjectionPointFinder,
    is_waf_block,
    redact,
)
from hydra.attack.detection import CONFIRMED, REFUTED, SUSPECTED
from hydra.attack.report_builder import record_outcome
from hydra.attack_runtime.session import SessionContext


# ── #1 differential detection ────────────────────────────────────────────────────
def test_differential_confirms_reflection():
    d = DifferentialDetector()
    base = {"executed": True, "status": 200, "length": 100, "body_snippet": "hello world"}
    resp = {"executed": True, "status": 200, "length": 120, "body_snippet": "hello <x> world"}
    assert d.decide("xss", base, "<x>", resp)[0] == CONFIRMED


def test_differential_refutes_no_signal():
    d = DifferentialDetector()
    same = {"executed": True, "status": 200, "length": 100, "body_snippet": "same body"}
    assert d.decide("xss", same, "<x>", same)[0] == REFUTED


def test_differential_sqli_error_and_time():
    d = DifferentialDetector()
    base = {"executed": True, "status": 200, "length": 50, "elapsed_ms": 30, "body_snippet": "ok"}
    err = {"executed": True, "status": 500, "length": 50, "elapsed_ms": 30,
           "body_snippet": "you have an error in your sql syntax near"}
    assert d.decide("sqli", base, "'", err)[0] == CONFIRMED
    slow = {"executed": True, "status": 200, "length": 50, "elapsed_ms": 5200, "body_snippet": "ok"}
    assert d.decide("sqli", base, "' AND SLEEP(5)--", slow)[0] == CONFIRMED


def test_differential_lfi_marker():
    d = DifferentialDetector()
    base = {"executed": True, "status": 200, "length": 10, "body_snippet": "nope"}
    hit = {"executed": True, "status": 200, "length": 99, "body_snippet": "root:x:0:0:root:/root"}
    assert d.decide("lfi", base, "../../etc/passwd", hit)[0] == CONFIRMED


def test_differential_suspected_on_status_flip():
    d = DifferentialDetector()
    base = {"executed": True, "status": 200, "length": 100, "body_snippet": "a"}
    flip = {"executed": True, "status": 500, "length": 100, "body_snippet": "a"}
    assert d.decide("xss", base, "<x>", flip)[0] == SUSPECTED


# ── #5 WAF signal ────────────────────────────────────────────────────────────────
def test_is_waf_block():
    assert is_waf_block({"status": 403}) is True
    assert is_waf_block({"status": 429}) is True
    assert is_waf_block({"status": 200, "body_snippet": "Attention Required! | Cloudflare"}) is True
    assert is_waf_block({"status": 200, "body_snippet": "normal page"}) is False


# ── #2 access control ────────────────────────────────────────────────────────────
def test_access_control_confirmed_by_marker():
    a = AccessControlAnalyzer()
    owner = {"executed": True, "status": 200, "length": 50}
    other = {"executed": True, "status": 200, "length": 50, "body_snippet": "ssn=alice-secret"}
    assert a.decide(owner, other, owner_markers=["ssn=alice-secret"])[0] == CONFIRMED


def test_access_control_refuted_when_denied():
    a = AccessControlAnalyzer()
    owner = {"executed": True, "status": 200, "length": 50}
    other = {"executed": True, "status": 403, "length": 5}
    assert a.decide(owner, other)[0] == REFUTED


# ── #4 injection points ──────────────────────────────────────────────────────────
def test_injection_points_cover_locations():
    req = {"method": "POST", "url": "https://x/api/v1?id=1&q=2",
           "headers": {"Cookie": "sid=abc", "Content-Type": "application/json"},
           "body": '{"name":"x","nested":{"k":"v"}}'}
    pts = InjectionPointFinder().find(req)
    locs = {p.location for p in pts}
    assert {"query", "json", "cookie", "header", "path"} <= locs
    names = {(p.location, p.name) for p in pts}
    assert ("query", "id") in names and ("json", "nested.k") in names and ("cookie", "sid") in names


def test_injection_point_apply_injects():
    req = {"method": "GET", "url": "https://x/?id=1", "headers": {}}
    pt = next(p for p in InjectionPointFinder().find(req) if p.name == "id")
    out = pt.apply("PWN")
    assert "id=PWN" in out["url"]


# ── #6 chain execution + redaction ───────────────────────────────────────────────
def test_redact_masks_secrets():
    assert "REDACTED" in redact('"SecretAccessKey":"abcd1234"')
    assert "AKIA" in redact("AKIAIOSFODNN7EXAMPLE") and "EXAMPLE" not in redact("AKIAIOSFODNN7EXAMPLE")
    assert "REDACTED" in redact("password=hunter2")


def test_chain_execute_depth_with_stub_workflow():
    class StubWF:
        def scan(self, target, vc, **k):
            return {"confirmed": vc == "ssrf", "authorized": True,
                    "evidence": [{"response": {"body_snippet": "SecretAccessKey:abc"}}]}
    out = ChainExecutor(StubWF()).execute("https://x", "ssrf_imds_takeover")
    assert out["demonstrated_depth"] == 1 and out["total_stages"] == 3
    # evidence redacted
    assert "REDACTED" in json.dumps(out["stages"])


def test_chain_execute_unknown():
    class StubWF:
        def scan(self, *a, **k):
            return {}
    assert ChainExecutor(StubWF()).execute("x", "nope")["error"] == "unknown chain template"


# ── #7 report builder ────────────────────────────────────────────────────────────
def test_report_severity_elevated_by_chain():
    rep = AttackReporter().build("acme",
        [{"vuln_class": "xss", "verdict": "confirmed", "point": "q",
          "evidence": {"curl": "curl x", "indicators": ["reflected"]}},
         {"vuln_class": "sqli", "verdict": "suspected"}],
        chains=[{"realized_severity": "critical"}])
    assert rep["overall_severity"] == "critical"          # elevated above base xss=medium
    assert len(rep["confirmed_findings"]) == 1 and len(rep["suspected_findings"]) == 1
    assert rep["confirmed_findings"][0]["remediation"]


def test_record_outcome_never_raises():
    record_outcome("acme", "xss", "confirmed", "q", {"response": {"status": 200}})  # must not raise


# ── #2 session merge ─────────────────────────────────────────────────────────────
def test_session_apply_merges_auth():
    s = SessionContext(name="alice", bearer="tok", cookies={"sid": "x"}, headers={"X-Role": "admin"})
    out = s.apply({"method": "GET", "url": "https://x", "headers": {"Cookie": "existing=1"}})
    assert out["headers"]["Authorization"] == "Bearer tok"
    assert out["headers"]["X-Role"] == "admin"
    assert "sid=x" in out["headers"]["Cookie"] and "existing=1" in out["headers"]["Cookie"]
    assert out["identity"] == "alice"
