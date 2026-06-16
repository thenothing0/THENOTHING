"""
Advanced attack improvements — pure-logic tests (network-free, deterministic).

Two-signal confirmation (#1), detection depth (#4: boolean-blind + content-type-aware signals),
specialized testers (#3: GraphQL / JWT / CORS / cache / host / smuggling-plan), RBAC (#5),
knowledge-graph loop-back (#2), and reporting maturity (#6: CVSS / dedup / templates).
"""

import base64
import hashlib
import hmac

from hydra.attack import (
    AttackReporter,
    CachePoisonProbe,
    CORSProbe,
    DifferentialDetector,
    FindingPublisher,
    GraphQLTester,
    HostHeaderProbe,
    JWTAnalyzer,
    PrivilegeEscalationTester,
    Signal,
    SmugglingPlan,
    TwoSignalConfirmer,
)
from hydra.attack.jwt_attacks import _enc


# ── #1 two-signal ────────────────────────────────────────────────────────────────
def test_two_signal_needs_two_independent_families():
    ts = TwoSignalConfirmer()
    assert ts.assess([Signal("reflection")]).verdict == "single_signal"
    assert ts.assess([Signal("reflection"), Signal("differential_length")]).verdict == "single_signal"
    assert ts.assess([Signal("reflection"), Signal("dom_execution")]).verdict == "confirmed"
    assert ts.assess([]).verdict == "unconfirmed"


# ── #4 detection depth ───────────────────────────────────────────────────────────
def test_signals_content_type_aware():
    d = DifferentialDetector()
    base = {"executed": True, "body_snippet": "x", "status": 200}
    html = {"executed": True, "body_snippet": "<s>", "status": 200, "content_type": "text/html"}
    js = {"executed": True, "body_snippet": "<s>", "status": 200, "content_type": "application/json"}
    assert any(s.kind == "reflection" for s in d.signals("xss", base, "<s>", html))
    assert not any(s.kind == "reflection" for s in d.signals("xss", base, "<s>", js))


def test_boolean_blind_sqli():
    d = DifferentialDetector()
    t = {"executed": True, "status": 200, "length": 500, "body_snippet": "welcome admin"}
    f = {"executed": True, "status": 200, "length": 80, "body_snippet": "invalid"}
    assert d.boolean_blind(t, f)[0] is True
    assert d.boolean_blind(t, t)[0] is False


# ── #3 GraphQL / JWT / web probes ────────────────────────────────────────────────
def test_graphql_requests_and_analyze():
    g = GraphQLTester()
    assert len(g.requests("https://x/graphql")) == 4
    assert g.analyze("introspection", {"executed": True,
                     "body_snippet": '{"data":{"__schema":{"types":[]}}}'})[0] == "confirmed"
    assert g.analyze("field_suggestion", {"executed": True,
                     "body_snippet": 'Did you mean "name"?'})[0] == "confirmed"


def test_jwt_decode_crack_forge():
    h, p = _enc({"alg": "HS256", "typ": "JWT"}), _enc({"user": "guest"})
    sig = base64.urlsafe_b64encode(
        hmac.new(b"secret", f"{h}.{p}".encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
    token = f"{h}.{p}.{sig}"
    ja = JWTAnalyzer()
    assert ja.crack_weak_secret(token) == "secret"
    assert ja.forge_none(token).endswith(".")
    assert ja.forge_alg_confusion(token, "PUBKEY").count(".") == 2
    assert "kid" in ja.decode(ja.inject_kid(token))["header"]
    assert "weak HMAC secret: 'secret'" in ja.analyze(token)["candidate_attacks"]


def test_web_probes():
    assert CORSProbe().analyze({"executed": True, "acao": "https://evil.example.com",
                                "acac": "true"})[0] == "confirmed"
    assert CachePoisonProbe().analyze({"executed": True, "body_snippet": "hydracachemarker.example",
                                       "x_cache": "HIT"})[0] == "confirmed"
    assert HostHeaderProbe().analyze({"executed": True,
                                      "body_snippet": "hydrahostmarker.example"})[0] == "confirmed"
    plan = SmugglingPlan().plan("https://x")
    assert "ADVISORY" in plan["warning"] and len(plan["techniques"]) == 3   # plan-only, never sent


# ── #5 RBAC / priv-esc ───────────────────────────────────────────────────────────
def test_privesc_flags_reachable_privileged_path():
    class _Sess:
        name = "low"

        def apply(self, req):
            return req

    def executor(req):
        return {"executed": True, "status": 200 if "/admin" in req["url"] else 403, "length": 10}

    out = PrivilegeEscalationTester(executor).test("https://x", _Sess(), paths=["/admin", "/public"])
    assert out["confirmed"] is True
    assert any(e["path"] == "/admin" for e in out["escalations"])


# ── #2 knowledge-graph loop-back ─────────────────────────────────────────────────
def test_publisher_writes_only_confirmed():
    calls = []
    pub = FindingPublisher(save_fn=lambda *a: calls.append(a))
    out = pub.publish("acme", [
        {"vuln_class": "xss", "verdict": "confirmed", "point": "q",
         "evidence": {"curl": "curl x", "reason": "two signals"}},
        {"vuln_class": "sqli", "verdict": "suspected"}])
    assert out["saved"] == 1 and out["skipped_unconfirmed"] == 1
    assert len(calls) == 1 and calls[0][0].startswith("XSS")    # only the confirmed one written


# ── #6 reporting maturity ────────────────────────────────────────────────────────
def test_cvss_dedup_and_markdown():
    r = AttackReporter()
    findings = [{"vuln_class": "sqli", "verdict": "confirmed", "point": "id",
                 "evidence": {"curl": "curl x", "indicators": ["db error"]}},
                {"vuln_class": "sqli", "verdict": "confirmed", "point": "id", "evidence": {}}]
    rep = r.build("acme", findings)
    assert len(rep["confirmed_findings"]) == 1                  # deduped by (class, point)
    assert rep["confirmed_findings"][0]["cvss"]["score"] == 9.8
    assert "CWE-89" in rep["confirmed_findings"][0]["cvss"]["cwe"]
    md = r.to_markdown(rep, "hackerone")
    assert "CVSS" in md and "Remediation" in md
