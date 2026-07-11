"""
Round-3 attack-section additions — pure-logic tests (network-free, deterministic).

Covers the four audit improvements built in this round:
  #5 injection variants (NoSQL / LDAP / prototype pollution) — detection signals + payloads + CVSS;
  #3 OWASP API Top 10 (BOLA / BFLA / mass-assignment / excessive-data-exposure) via a fake executor;
  #4 scan robustness (response normalization, cross-run scan state);
  #6 auth-protocol (OAuth/OIDC analysis + redirect_uri test, SAML analysis + XSW vectors).

Live end-to-end paths (through the gated HttpExecutor + a local server) live in tests/attack_runtime/.
"""

import gzip

import pytest

from hydra.attack import (
    APIAttackTester,
    AttackReporter,
    DifferentialDetector,
    OAuthTester,
    ResponseNormalizer,
    SAMLAnalyzer,
    ScanState,
)
from hydra.attack.detection import CONFIRMED
from hydra.attack.payloads import PayloadContext, PayloadLibrary, VulnClass
from hydra.attack_runtime.session import SessionContext
from hydra.authorization import BugBountyAuthorizationGate


# ── #5 injection variants ───────────────────────────────────────────────────────
def test_nosql_error_confirms():
    d = DifferentialDetector()
    base = {"executed": True, "status": 200, "length": 10, "body_snippet": "ok"}
    hit = {"executed": True, "status": 500, "length": 80,
           "body_snippet": "MongoError: unexpected token in $where"}
    assert d.decide("nosqli", base, '{"$ne":null}', hit)[0] == CONFIRMED
    fams = {s.family for s in d.signals("nosqli", base, '{"$ne":null}', hit)}
    assert "error" in fams and "behavioural" in fams        # error + status flip = two-signal


def test_ldap_error_confirms():
    d = DifferentialDetector()
    base = {"executed": True, "status": 200, "length": 10, "body_snippet": "ok"}
    hit = {"executed": True, "status": 200, "length": 10,
           "body_snippet": "javax.naming.directory: invalid DN syntax"}
    assert d.decide("ldapi", base, "*)(uid=*", hit)[0] == CONFIRMED


def test_prototype_pollution_marker_only_under_injection():
    d = DifferentialDetector()
    base = {"executed": True, "status": 200, "length": 10, "body_snippet": "{}"}
    hit = {"executed": True, "status": 200, "length": 30, "body_snippet": '{"hydrapp":"polluted"}'}
    assert d.decide("prototype_pollution", base, "__proto__[hydrapp]=polluted", hit)[0] == CONFIRMED


def test_new_classes_have_payloads_and_cvss():
    for vc in ("nosqli", "ldapi", "prototype_pollution"):
        assert PayloadLibrary().for_context(VulnClass(vc), PayloadContext.ANY)
        assert AttackReporter.cvss(vc)["score"] > 0


# ── #4 response normalization + scan state ───────────────────────────────────────
def test_normalizer_gunzips_and_charset():
    n = ResponseNormalizer()
    raw = gzip.compress("<html>héllo</html>".encode("latin-1"))
    text = n.decode(raw, "gzip", "text/html; charset=latin-1")
    assert "héllo" in text


def test_normalizer_detects_spa_shell():
    n = ResponseNormalizer()
    spa = '<html><body><div id="root"></div><script src="/static/bundle.js"></script></body></html>'
    assert n.is_spa_shell(spa) is True
    assert n.is_spa_shell("<html><body>real server-rendered content here</body></html>") is False


def test_scan_state_roundtrip(tmp_path):
    st = ScanState(path=tmp_path / "s.jsonl")
    assert st.seen("http://x/a", "xss") is False
    st.mark("http://x/a", "xss", "*", "scanned")
    assert st.seen("http://x/a", "xss") is True
    # a fresh instance reads the persisted state (cross-run resume)
    assert ScanState(path=tmp_path / "s.jsonl").seen("http://x/a", "xss") is True


# ── #3 OWASP API Top 10 (fake executor) ──────────────────────────────────────────
class _FakeExec:
    """Routes a request dict to a canned response by (method, url-substring)."""
    def __init__(self, routes):
        self.routes = routes

    def __call__(self, req):
        for (method, frag), resp in self.routes.items():
            if (req.get("method", "GET").upper() == method) and frag in req.get("url", ""):
                return {"executed": True, **resp}
        return {"executed": True, "status": 404, "length": 0, "body_snippet": "nope"}


@pytest.fixture
def gate(tmp_path, monkeypatch):
    monkeypatch.setenv("HYDRA_AUTHORIZED_PROGRAMS", str(tmp_path / "p.json"))
    g = BugBountyAuthorizationGate()
    g.register_program("local", "custom", in_scope=["api.example.com"])
    return g


def test_bola_confirmed_when_b_gets_a_resource(gate):
    ex = _FakeExec({("GET", "/doc/1"): {"status": 200, "length": 50,
                                        "body_snippet": "owner:alice secret-alice"}})
    a = SessionContext("alice", cookies={"uid": "a"})
    b = SessionContext("bob", cookies={"uid": "b"})
    res = APIAttackTester(ex, gate=gate).bola("https://api.example.com/doc/1", a, b,
                                              owner_markers=["secret-alice"])
    assert res["confirmed"] is True


def test_bfla_flags_low_priv_function(gate):
    ex = _FakeExec({("GET", "/api/admin"): {"status": 200, "length": 30, "body_snippet": "admin"}})
    low = SessionContext("user", cookies={"uid": "u"})
    res = APIAttackTester(ex, gate=gate).bfla("https://api.example.com",
                                              low, functions=[("GET", "/api/admin")])
    assert res["confirmed"] is True and res["results"][0]["bfla"] is True


def test_mass_assignment_confirmed_on_reflection(gate):
    ex = _FakeExec({("PATCH", "/users/me"): {"status": 200, "length": 40,
                                             "body_snippet": '{"name":"x","role":"admin"}'}})
    res = APIAttackTester(ex, gate=gate).mass_assignment(
        "https://api.example.com/users/me", SessionContext("u"), base_body={"name": "x"})
    assert res["confirmed"] is True and "role" in res["reflected_privileged_fields"]


def test_excessive_data_exposure_finds_sensitive_key(gate):
    ex = _FakeExec({("GET", "/me"): {"status": 200, "length": 60,
                                     "body_snippet": '{"id":1,"email":"a@b.c","password_hash":"x"}'}})
    res = APIAttackTester(ex, gate=gate).excessive_data_exposure("https://api.example.com/me")
    assert res["confirmed"] is True and "password_hash" in res["leaked_sensitive_fields"]


def test_api_deny_by_default(tmp_path, monkeypatch):
    monkeypatch.setenv("HYDRA_AUTHORIZED_PROGRAMS", str(tmp_path / "empty.json"))
    g = BugBountyAuthorizationGate()
    res = APIAttackTester(_FakeExec({}), gate=g).bola(
        "https://not-in-scope.com/x", SessionContext("a"), SessionContext("b"))
    assert res["authorized"] is False


# ── #6 auth-protocol ─────────────────────────────────────────────────────────────
def test_oauth_static_flags_missing_state_and_pkce():
    url = "https://idp.example.com/authorize?response_type=code&client_id=x&redirect_uri=https://app/cb"
    w = {x["issue"] for x in OAuthTester().analyze(url)["weaknesses"]}
    assert "missing_state" in w and "missing_pkce" in w


def test_oauth_redirect_uri_honoured_is_confirmed(gate):
    g = gate
    g.register_program("idp", "custom", in_scope=["idp.example.com"])
    # server 302s to whatever redirect_uri we pass → honours the attacker host
    ex = _FakeExec({("GET", "/authorize"): {"status": 302, "length": 0, "body_snippet": "",
                                            "location": "https://evil.example.com/cb"}})
    url = "https://idp.example.com/authorize?response_type=code&redirect_uri=https://app/cb&state=s"
    res = OAuthTester(executor=ex, gate=g).test_redirect_uri(url)
    assert res["confirmed"] is True


def test_saml_unsigned_and_xsw_vectors():
    import base64
    xml = b"<samlp:Response><saml:Assertion>x</saml:Assertion></samlp:Response>"
    res = SAMLAnalyzer().analyze(base64.b64encode(xml).decode())
    assert any(x["issue"] == "unsigned_assertion" for x in res["weaknesses"])
    assert any(v["name"] == "XSW1" for v in res["xsw_vectors"])
