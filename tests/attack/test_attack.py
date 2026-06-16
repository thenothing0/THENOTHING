"""
Attack section tests.

Covers the seven improvements (guarded workflow / OOB / context payloads / 403 bypass / chain
templates / evidence / attack queue) plus the safety properties that make them acceptable: the
workflow is DENY-BY-DEFAULT and PoC-only, the default executor sends NOTHING (no network), payloads
are detection/PoC grade, and everything is deterministic.
"""

import json

import pytest

from hydra.attack import (
    AttackQueue,
    AttackWorkflow,
    Bypass403Generator,
    ChainTemplateEngine,
    EvidenceCollector,
    ListenerConfig,
    OOBCorrelator,
    PayloadContext,
    PayloadLibrary,
    VulnClass,
    curl_repro,
)
from hydra.authorization import BugBountyAuthorizationGate


@pytest.fixture
def gate(tmp_path, monkeypatch):
    monkeypatch.setenv("HYDRA_AUTHORIZED_PROGRAMS", str(tmp_path / "programs.json"))
    g = BugBountyAuthorizationGate()
    g.register_program("acme", "hackerone", in_scope=["*.acme.com"])
    return g


# ── #3 context-aware payloads ────────────────────────────────────────────────────
def test_payloads_are_context_aware(gate):
    lib = PayloadLibrary()
    attr = lib.for_context(VulnClass.XSS, PayloadContext.HTML_ATTR)
    body = lib.for_context(VulnClass.XSS, PayloadContext.HTML_BODY)
    assert attr and body
    assert {p.context for p in attr} <= {"html_attr", "any", "polyglot"}


def test_payloads_are_poc_grade_not_destructive():
    lib = PayloadLibrary()
    for vc in VulnClass:
        for p in lib.for_context(vc):
            blob = p.value.lower()
            assert p.poc is True
            for destructive in ("drop table", "delete from", "rm -rf", "shutdown", "truncate "):
                assert destructive not in blob


def test_waf_adapted_variants_deterministic():
    lib = PayloadLibrary()
    a = lib.waf_adapted("' OR '1'='1", "cloudflare")
    b = lib.waf_adapted("' OR '1'='1", "cloudflare")
    assert a == b and a[0] == "' OR '1'='1"          # original first, deterministic order


# ── #4 403/WAF bypass ────────────────────────────────────────────────────────────
def test_waf_bypass_covers_all_categories():
    rep = Bypass403Generator().report("https://acme.com/admin")
    assert set(rep["by_category"]) == {"path-based", "method-based", "header-based",
                                       "host-header", "encoding", "root-only"}
    assert rep["count"] >= 25


def test_waf_bypass_analyze_separates_waf_from_backend():
    out = Bypass403Generator.analyze(
        {"status": 403},
        [{"technique": "header", "status": 200, "length": 9},
         {"technique": "method", "status": 403, "length": 1}])
    assert out["bypassed"] is True and out["backend_reached"] == ["header"]


# ── #2 OOB / blind detection ─────────────────────────────────────────────────────
def test_oob_token_deterministic_and_correlates():
    oc = OOBCorrelator(ListenerConfig(oob_domain="x.oast.live"))
    t1 = oc.mint("finding-9", "ssrf")
    t2 = OOBCorrelator(ListenerConfig(oob_domain="x.oast.live")).mint("finding-9", "ssrf")
    assert t1.token == t2.token                       # deterministic per finding
    assert oc.payloads("ssrf", t1.callback_url)
    corr = oc.correlate([{"host": t1.callback_host, "protocol": "dns"}])
    assert corr["count"] == 1 and corr["confirmed_blind_findings"][0]["finding_id"] == "finding-9"


def test_oob_default_listener_not_configured():
    assert OOBCorrelator().listener.configured is False     # no live server by default


# ── #5 chain templates + severity elevation ──────────────────────────────────────
def test_chain_template_instantiation_and_elevation():
    m = ChainTemplateEngine().match([{"vuln_class": "ssrf", "severity": "low"},
                                     {"vuln_class": "cloud_metadata"},
                                     {"vuln_class": "credential"}])
    assert m["instantiable_count"] >= 1
    chain = m["instantiable_chains"][0]
    assert chain["chain_id"] == "ssrf_imds_takeover"
    assert chain["severity_elevation"]["elevated"] is True
    assert chain["severity_elevation"]["to"] == "critical"
    assert chain["attack_techniques"]                  # ATT&CK-linked


def test_chain_partial_when_stage_missing():
    m = ChainTemplateEngine().match([{"vuln_class": "ssrf"}])   # missing later stages
    assert m["instantiable_count"] == 0
    assert any(p["chain_id"] == "ssrf_imds_takeover" for p in m["partial_chains"])


# ── #6 evidence ──────────────────────────────────────────────────────────────────
def test_evidence_curl_and_verdict():
    c = curl_repro("POST", "https://acme.com/x", {"X-Test": "1"}, "a=b")
    assert c.startswith("curl") and "-X POST" in c and "X-Test: 1" in c
    ev = EvidenceCollector().capture("xss", {"method": "GET", "url": "https://acme.com/?q=x"},
                                     {"status": 200, "length": 10},
                                     indicators=["reflected"], confirmed=True)
    assert ev.verdict == "confirmed"
    assert "CONFIRMED" in ev.render()


def test_evidence_suspected_without_indicators():
    ev = EvidenceCollector().capture("sqli", {"method": "GET", "url": "https://acme.com"},
                                     {"status": 200}, indicators=[], confirmed=None)
    assert ev.verdict == "suspected"


# ── #7 attack queue ──────────────────────────────────────────────────────────────
def test_queue_prioritizes_by_value():
    q = AttackQueue().prioritize("https://acme.com", [
        {"id": "f1", "vuln_class": "ssrf", "severity": "low"},
        {"id": "f2", "vuln_class": "cloud_metadata", "severity": "info"},
        {"id": "f3", "vuln_class": "credential", "severity": "info"}])
    assert q["count"] == 3
    scores = [r["priority"] for r in q["queue"]]
    assert scores == sorted(scores, reverse=True)
    assert all(0.0 <= s <= 1.0 for s in scores)
    # with all three stages present, ssrf feeds an instantiable critical chain → ranks high
    assert q["instantiable_chains"] >= 1


# ── #1 guarded workflow (the keystone) ───────────────────────────────────────────
def test_workflow_deny_by_default(gate, monkeypatch, tmp_path):
    # a fresh gate with NO program → deny
    empty = BugBountyAuthorizationGate(registry_path=str(tmp_path / "empty.json"))
    r = AttackWorkflow(gate=empty).run("https://anything.com", "xss")
    assert r.authorized is False and r.payloads == [] and r.executed is False


def test_workflow_authorized_is_poc_only_and_no_network(gate):
    r = AttackWorkflow(gate=gate).run("https://app.acme.com", "xss", context="html_attr",
                                      execute=True)
    assert r.authorized is True
    assert r.poc_only is True
    assert r.executed is False               # default DryRunExecutor sends NOTHING even with execute=True
    assert r.technique == "T1190"
    assert len(r.payloads) >= 1


def test_workflow_out_of_scope_denied(gate):
    r = AttackWorkflow(gate=gate).run("https://notacme.org", "sqli")
    assert r.authorized is False


def test_workflow_plan_is_json_serializable(gate):
    plan = AttackWorkflow(gate=gate).plan("https://app.acme.com", "ssrf", "url")
    json.dumps(plan)
    assert plan["authorized"] is True and plan["advisory"] is True


def test_injected_executor_only_runs_when_authorized(gate):
    calls = []

    def fake_executor(req):
        calls.append(req)
        return {"status": 200, "length": 5, "executed": True}

    wf = AttackWorkflow(gate=gate, executor=fake_executor)
    # denied target → executor must NOT be called
    wf.run("https://evil.com", "xss", execute=True)
    assert calls == []
    # authorized target → executor runs, evidence captured
    r = wf.run("https://app.acme.com", "xss", context="html_body", execute=True)
    assert r.executed is True and len(calls) == 1 and r.evidence is not None


# ── safety: store-free-ish, no exec/subprocess/network in the package source ──────
def test_package_has_no_execution_primitives():
    import pathlib
    pkg = pathlib.Path(__file__).resolve().parents[2] / "hydra" / "attack"
    forbidden = ["subprocess", "os.system", "popen", "exec(", "eval(",
                 "requests.", "urllib.request", "aiohttp", "socket."]
    for p in sorted(pkg.glob("*.py")):
        full = p.read_text(encoding="utf-8")
        for tok in forbidden:
            assert tok not in full, f"forbidden '{tok}' in attack/{p.name} (network/exec stays out)"
