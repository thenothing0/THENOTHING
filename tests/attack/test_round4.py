"""
Round-4 attack-section additions — pure-logic tests (network-free, deterministic).

  #1 stored / second-order detection (submit-at-A → observe-at-B, canary + DOM second signal);
  #2 parameter mining + JS endpoint/secret extraction;
  #3 detection fidelity (honeypot/trap guard, baseline-jitter, boolean-blind wired into scan);
  #5 GraphQL depth (mutations/alias batching) + auth/API chain templates.

Live end-to-end paths live in tests/attack_runtime/test_round4_live.py.
"""

import pytest

from hydra.attack import (
    AttackWorkflow,
    DifferentialDetector,
    GraphQLTester,
    HoneypotGuard,
    JSEndpointExtractor,
    ParameterMiner,
    StoredVulnTester,
)
from hydra.attack.chain_templates import ChainTemplateEngine
from hydra.attack_runtime.session import SessionContext
from hydra.authorization import BugBountyAuthorizationGate


@pytest.fixture
def gate(tmp_path, monkeypatch):
    monkeypatch.setenv("HYDRA_AUTHORIZED_PROGRAMS", str(tmp_path / "p.json"))
    g = BugBountyAuthorizationGate()
    g.register_program("local", "custom", in_scope=["app.example.com"])
    return g


# ── #3 honeypot / trap guard ─────────────────────────────────────────────────────
def test_honeypot_guard_flags_canned_sql_error():
    det = DifferentialDetector()
    base = {"executed": True, "status": 200, "length": 50, "body_snippet": "ok"}
    # endpoint returns a SQL error for ANY input → trap
    ex = lambda req: {"executed": True, "status": 200, "length": 80,
                      "body_snippet": "you have an error in your sql syntax near"}
    is_trap, reason = HoneypotGuard().probe(det, "sqli", base, lambda v: {"url": "x", "headers": {}}, ex)
    assert is_trap is True and "error_signature" in reason


def test_honeypot_guard_ignores_plain_reflection():
    det = DifferentialDetector()
    base = {"executed": True, "status": 200, "length": 50, "body_snippet": "ok"}
    # reflects input but no class-confirming signal → NOT a trap (normal reflective sink)
    ex = lambda req: {"executed": True, "status": 200, "length": 60,
                      "body_snippet": f"you said {req.get('payload','')}", "content_type": "text/html"}
    is_trap, _ = HoneypotGuard().probe(det, "xss", base, lambda v: {"url": "x", "headers": {},
                                                                    "payload": v}, ex)
    assert is_trap is False


# ── #3 baseline-jitter awareness ─────────────────────────────────────────────────
def test_length_delta_below_jitter_is_not_a_signal():
    det = DifferentialDetector()
    base = {"executed": True, "status": 200, "length": 1000, "body_snippet": "x",
            "length_jitter": 400}
    resp = {"executed": True, "status": 200, "length": 1300, "body_snippet": "x"}  # delta 300 < 400*1.5
    kinds = {s.kind for s in det.signals("xss", base, "p", resp)}
    assert "differential_length" not in kinds


# ── #3 boolean-blind wired into the scan loop ────────────────────────────────────
class _SqliFake:
    """Time-based + boolean-differential SQLi sink (keyed by the request payload)."""
    def __call__(self, req):
        p = req.get("payload", "")
        if p == "' AND '1'='1":
            return {"executed": True, "status": 200, "length": 200, "body_snippet": "many results"}
        if p == "' AND '1'='2":
            return {"executed": True, "status": 200, "length": 100, "body_snippet": "no results"}
        if "SLEEP" in p:
            return {"executed": True, "status": 200, "length": 100, "body_snippet": "ok",
                    "elapsed_ms": 5200}
        return {"executed": True, "status": 200, "length": 100, "body_snippet": "ok", "elapsed_ms": 10}


def test_scan_confirms_sqli_via_boolean_plus_timing(gate):
    wf = AttackWorkflow(gate=gate, executor=_SqliFake())
    res = wf.scan("https://app.example.com/item?id=1", "sqli", context="sql")
    assert res["confirmed"] is True
    fams = res["confirmed_findings"][0]["evidence"]["confirmation"]["families"]
    assert "timing" in fams and "behavioural" in fams        # SLEEP timing + boolean pair


# ── #1 stored / second-order ─────────────────────────────────────────────────────
class _StoreFake:
    """Persists the last submitted payload and reflects it on observe GETs."""
    def __init__(self):
        self.stored = ""
    def __call__(self, req):
        if (req.get("method") or "GET").upper() == "POST":
            self.stored = req.get("payload", "")
            return {"executed": True, "status": 200, "length": 10, "body_snippet": "saved"}
        return {"executed": True, "status": 200, "length": 50,
                "body_snippet": f"<html>{self.stored}</html>", "content_type": "text/html"}


def test_stored_xss_confirmed_with_dom(gate):
    fake = _StoreFake()
    tester = StoredVulnTester(gate=gate, executor=fake,
                              browser_confirmer=lambda url: {"confirmed": True})
    submit = {"method": "POST", "url": "https://app.example.com/profile",
              "body": "bio=x", "headers": {}}
    res = tester.test(submit, ["https://app.example.com/u/me"], vuln_class="xss", field="bio")
    assert res["persisted"] is True and res["confirmed"] is True


def test_stored_reflection_alone_is_suspected(gate):
    fake = _StoreFake()
    tester = StoredVulnTester(gate=gate, executor=fake)        # no DOM confirmer → one signal only
    submit = {"method": "POST", "url": "https://app.example.com/profile",
              "body": "bio=x", "headers": {}}
    res = tester.test(submit, ["https://app.example.com/u/me"], vuln_class="xss", field="bio")
    assert res["persisted"] is True and res["confirmed"] is False


# ── #2 parameter mining + JS extraction ──────────────────────────────────────────
class _ParamFake:
    """Reflects the canary VALUE back only when the `debug` parameter is present."""
    def __call__(self, req):
        from urllib.parse import parse_qs, urlparse
        q = parse_qs(urlparse(req.get("url", "")).query)
        if "debug" in q:
            return {"executed": True, "status": 200, "length": 80,
                    "body_snippet": f"debug echo {q['debug'][0]}"}
        return {"executed": True, "status": 200, "length": 50, "body_snippet": "ok"}


def test_param_miner_discovers_hidden_param(gate):
    res = ParameterMiner(gate=gate, executor=_ParamFake()).mine(
        "https://app.example.com/x", wordlist=["foo", "debug", "bar"], batch=10)
    assert any(d["param"] == "debug" and d["signal"] == "reflected" for d in res["discovered"])


def test_js_extractor_finds_endpoints_params_secrets():
    js = 'fetch("/api/v3/orders?status=open"); var t="AKIAIOSFODNN7EXAMPLE"; axios.get("/admin/users")'
    out = JSEndpointExtractor().extract(js)
    assert "/admin/users" in out["endpoints"] and "status" in out["params"]
    assert out["secret_count"] >= 1 and out["secrets"][0]["kind"] == "aws_access_key"


# ── #5 GraphQL depth + chains ────────────────────────────────────────────────────
def test_graphql_detects_mutations_and_alias_batching():
    t = GraphQLTester()
    assert t.analyze("mutations_exposed",
                     {"executed": True, "body_snippet": '{"data":{"__schema":{"mutationType":{"name":"Mutation"}}}}'})[0] == "confirmed"
    assert t.analyze("alias_batching",
                     {"executed": True, "body_snippet": '{"data":{"hydra0":"Query","hydra1":"Query","hydra2":"Query"}}'})[0] == "confirmed"


def test_auth_chain_templates_instantiate():
    m = ChainTemplateEngine().match([{"vuln_class": "oauth"}, {"vuln_class": "open_redirect"}])
    ids = [c["chain_id"] for c in m["instantiable_chains"]]
    assert "oauth_redirect_ato" in ids
    assert m["instantiable_chains"][0]["realized_severity"] in ("critical", "high")
