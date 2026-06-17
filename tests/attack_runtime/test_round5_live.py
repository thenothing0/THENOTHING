"""
Round-5 additions — live end-to-end through the gated HttpExecutor + a local server.

The app simulates: a CSRF-unprotected state-changing endpoint (accepts any POST), a password-reset
endpoint that reflects the X-Forwarded-Host (host-header poisoning), and a login that sets an insecure
session cookie. Confirms CSRF / reset-poisoning detection and the cookie audit over real HTTP (the
executor now surfaces Set-Cookie), and that everything stays deny-by-default.
"""

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

import pytest

from hydra.attack import CookieAuditor, CSRFTester, PasswordResetPoisoning
from hydra.attack_runtime import HttpExecutor, SessionContext
from hydra.authorization import BugBountyAuthorizationGate


class _App(BaseHTTPRequestHandler):
    def do_GET(self):
        if urlparse(self.path).path == "/login":
            self.send_response(200)
            self.send_header("Set-Cookie", "sessionid=abc123; Path=/")     # insecure session cookie
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self._send(404, "nope")

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        self.rfile.read(n)
        path = urlparse(self.path).path
        if path == "/transfer":
            self._send(200, "transferred")                                 # accepts any POST → CSRF
        elif path == "/forgot":
            host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or ""
            self._send(200, f"reset link https://{host}/reset?t=tok")       # host reflected
        else:
            self._send(404, "nope")

    def _send(self, code, body):
        b = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def server():
    srv = HTTPServer(("127.0.0.1", 0), _App)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


@pytest.fixture
def gate(tmp_path, monkeypatch):
    monkeypatch.setenv("HYDRA_AUTHORIZED_PROGRAMS", str(tmp_path / "p.json"))
    g = BugBountyAuthorizationGate()
    g.register_program("local", "custom", in_scope=["127.0.0.1"])
    return g


def test_csrf_live(gate, server):
    ex = HttpExecutor(gate=gate, rate_per_sec=0)
    res = CSRFTester(gate=gate, executor=ex).test(
        {"method": "POST", "url": f"{server}/transfer", "body": "amt=1&csrf=good"},
        csrf_field="csrf", session=SessionContext("u", cookies={"sid": "x"}))
    assert res["confirmed"] is True


def test_reset_poisoning_live(gate, server):
    ex = HttpExecutor(gate=gate, rate_per_sec=0)
    res = PasswordResetPoisoning(gate=gate, executor=ex).test(
        f"{server}/forgot", evil_host="evil.example.com")
    assert res["confirmed"] is True
    assert any(r["header"] == "X-Forwarded-Host" for r in res["confirmed_findings"])


def test_cookie_audit_live(gate, server):
    ex = HttpExecutor(gate=gate, rate_per_sec=0)
    resp = ex({"method": "GET", "url": f"{server}/login", "headers": {}})
    audit = CookieAuditor().audit(resp.get("set_cookie", []))
    assert audit["confirmed"] is True
    assert any(c["cookie"] == "sessionid" for c in audit["flagged"])


def test_csrf_deny_by_default(tmp_path, monkeypatch, server):
    monkeypatch.setenv("HYDRA_AUTHORIZED_PROGRAMS", str(tmp_path / "empty.json"))
    g = BugBountyAuthorizationGate()
    res = CSRFTester(gate=g, executor=HttpExecutor(gate=g)).test(
        {"method": "POST", "url": f"{server}/transfer"})
    assert res["authorized"] is False
