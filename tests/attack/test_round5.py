"""
Round-5 attack-section additions — pure-logic tests (network-free, deterministic).

  #1 replayable PoC bundle + finding re-verification;
  #2 program-aware severity + submission-readiness gate;
  #3 finding correlation / dedup by root cause;
  #4 CSRF / cookie-audit / password-reset-poisoning;
  #5 fingerprint-driven class recommendation + payload prioritization.
"""

import pytest

from hydra.attack import (
    CookieAuditor,
    CSRFTester,
    FindingCorrelator,
    FindingReverifier,
    FingerprintPayloadSelector,
    PasswordResetPoisoning,
    SubmissionReadiness,
    build_bundle,
    program_severity,
)
from hydra.attack_runtime.session import SessionContext
from hydra.authorization import BugBountyAuthorizationGate


@pytest.fixture
def gate(tmp_path, monkeypatch):
    monkeypatch.setenv("HYDRA_AUTHORIZED_PROGRAMS", str(tmp_path / "p.json"))
    g = BugBountyAuthorizationGate()
    g.register_program("local", "custom", in_scope=["app.example.com"])
    return g


_CONFIRMED = {
    "vuln_class": "xss", "verdict": "confirmed", "point": "q",
    "evidence": {"request": {"method": "GET", "url": "https://app.example.com/s?q=<x>",
                             "headers": {}, "payload": "<x>"},
                 "response": {"status": 200, "length": 50}, "curl": "curl 'https://app.example.com/s?q=<x>'",
                 "indicators": ["reflected", "dom executed"],
                 "confirmation": {"independent_signals": 2, "families": ["reflection", "execution"]}},
}


# ── #1 PoC bundle + reverify ─────────────────────────────────────────────────────
def test_build_bundle_is_self_contained():
    b = build_bundle(_CONFIRMED)
    assert b["curl"].startswith("curl") and b["replay_request"]["url"].endswith("q=<x>")
    assert "PoC" in b["markdown"] and b["shell"].startswith("#!/bin/sh")


class _ReFake:
    """SQLi sink: the injected request errors; the benign baseline does not."""
    def __call__(self, req):
        if "1=1" in req.get("url", "") or "OR" in (req.get("payload") or ""):
            return {"executed": True, "status": 500, "length": 80,
                    "body_snippet": "you have an error in your sql syntax near"}
        return {"executed": True, "status": 200, "length": 50, "body_snippet": "ok"}


def test_reverify_reproduces_finding(gate):
    finding = {"vuln_class": "sqli", "verdict": "confirmed",
               "evidence": {"request": {"method": "GET",
                                        "url": "https://app.example.com/x?id=' OR 1=1",
                                        "payload": "' OR 1=1", "headers": {}}}}
    res = FindingReverifier(gate=gate, executor=_ReFake()).reverify(finding)
    assert res["reproduces"] is True and res["verdict"] == "confirmed"


def test_reverify_deny_by_default(tmp_path, monkeypatch):
    monkeypatch.setenv("HYDRA_AUTHORIZED_PROGRAMS", str(tmp_path / "e.json"))
    g = BugBountyAuthorizationGate()
    res = FindingReverifier(gate=g, executor=_ReFake()).reverify(
        {"vuln_class": "sqli", "evidence": {"request": {"url": "https://nope.com/x?id=1"}}})
    assert res["authorized"] is False


# ── #2 program severity + readiness ──────────────────────────────────────────────
def test_program_severity_bands():
    assert program_severity(9.8)["p_scale"] == "P1"
    assert program_severity(8.1, "hackerone")["hackerone_severity"] == "High"
    assert program_severity(5.0)["p_scale"] == "P3"


def test_readiness_blocks_without_two_signals(gate):
    weak = {"vuln_class": "xss", "verdict": "confirmed",
            "evidence": {"curl": "curl x", "request": {"url": "https://app.example.com/s"},
                         "confirmation": {"independent_signals": 1}}}
    r = SubmissionReadiness().assess(weak, "https://app.example.com/s", gate)
    assert r["ready"] is False and "two_independent_signals" in r["blockers"]


def test_readiness_passes_complete_finding(gate):
    r = SubmissionReadiness().assess(_CONFIRMED, "https://app.example.com/s", gate)
    assert r["ready"] is True and r["readiness_score"] == 1.0


# ── #3 correlation ───────────────────────────────────────────────────────────────
def test_correlator_merges_same_endpoint_diff_ids():
    fs = [{"vuln_class": "idor", "verdict": "confirmed",
           "evidence": {"request": {"url": "https://a/api/user/12"}}},
          {"vuln_class": "idor", "verdict": "confirmed",
           "evidence": {"request": {"url": "https://a/api/user/99"}}}]
    m = FindingCorrelator().merge(fs)
    assert m["merged_count"] == 1 and m["duplicates_collapsed"] == 1
    assert m["merged_findings"][0]["instance_count"] == 2


# ── #4 CSRF / cookies / reset poisoning ──────────────────────────────────────────
class _CSRFFake:
    """Accepts the state-changing request no matter the token / origin → no CSRF protection."""
    def __call__(self, req):
        return {"executed": True, "status": 200, "length": 10, "body_snippet": "ok"}


def test_csrf_confirmed_when_accepted_tokenless_and_cross_origin(gate):
    res = CSRFTester(gate=gate, executor=_CSRFFake()).test(
        {"method": "POST", "url": "https://app.example.com/transfer", "body": "amt=1&csrf=good"},
        csrf_field="csrf", session=SessionContext("u", cookies={"sid": "x"}))
    assert res["confirmed"] is True and "no_token" in res["accepting_variants"]


def test_cookie_audit_flags_insecure_session_cookie():
    a = CookieAuditor().audit(["sessionid=abc; Path=/", "csrftoken=x; HttpOnly; SameSite=None"])
    issues = {c["cookie"]: c["issues"] for c in a["cookies"]}
    assert "missing Secure" in issues["sessionid"] and "missing HttpOnly" in issues["sessionid"]
    assert "SameSite=None without Secure" in issues["csrftoken"]   # SameSite=None needs Secure


class _ResetFake:
    """Reflects whatever Host-ish header is sent (host-header poisoning)."""
    def __call__(self, req):
        h = {k.lower(): v for k, v in (req.get("headers") or {}).items()}
        host = h.get("x-forwarded-host") or h.get("host") or ""
        return {"executed": True, "status": 200, "length": 40,
                "body_snippet": f"reset link https://{host}/reset?t=abc"}


def test_reset_poisoning_confirmed_on_reflected_host(gate):
    res = PasswordResetPoisoning(gate=gate, executor=_ResetFake()).test(
        "https://app.example.com/forgot", evil_host="evil.example.com")
    assert res["confirmed"] is True


# ── #5 fingerprint selection ─────────────────────────────────────────────────────
def test_fingerprint_recommends_relevant_classes():
    classes = [c["vuln_class"] for c in
               FingerprintPayloadSelector().recommend_classes("express node.js mongodb")]
    assert "nosqli" in classes and "prototype_pollution" in classes


def test_fingerprint_prioritizes_stack_payloads():
    out = FingerprintPayloadSelector().prioritize_payloads(
        "sqli", "postgres", ["' AND SLEEP(5)-- -", "' UNION SELECT version()-- -"])
    assert "version()" in out[0]                       # postgres payload floated to front
