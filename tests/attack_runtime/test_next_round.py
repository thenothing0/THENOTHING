"""
Crawl-seeded scanning + OOB poller + login-flow automation (live, through local stub servers).
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from hydra.attack import AttackWorkflow
from hydra.attack.oob import ListenerConfig, OOBCorrelator
from hydra.attack_runtime import HttpExecutor, LoginFlow, OOBConfirmer, OOBPoller
from hydra.authorization import BugBountyAuthorizationGate


class _App(BaseHTTPRequestHandler):
    def do_GET(self):
        path, q = urlparse(self.path).path, parse_qs(urlparse(self.path).query)
        if path == "/poll":                                   # OOB collaborator stub
            tok = q.get("id", [""])[0]
            self._json({"interactions": [{"host": f"{tok}.oob.example", "protocol": "dns",
                                          "remote_addr": "9.9.9.9"}]})
        elif path == "/search":
            self._html(200, f"<html>{q.get('q', [''])[0]}</html>")
        else:
            self._html(404, "no")

    def do_POST(self):
        if urlparse(self.path).path == "/login":
            self.send_response(200)
            self.send_header("Set-Cookie", "session=ABC123; HttpOnly")
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"access_token":"jwt-xyz"}')
        else:
            self._html(404, "no")

    def _html(self, c, b):
        self.send_response(c)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b.encode())

    def _json(self, o):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(o).encode())

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


# ── crawl-seeded scanning ────────────────────────────────────────────────────────
def test_scan_many_dedups_and_scans(gate, server):
    wf = AttackWorkflow(gate=gate, executor=HttpExecutor(gate=gate, rate_per_sec=0))
    urls = [f"{server}/search?q=1", f"{server}/search?q=2", f"{server}/static.js"]
    res = wf.scan_many(urls, "xss", context="html_body")
    assert res["distinct_seeds"] == 1                       # the two /search dedupe; static dropped
    assert res["confirmed"] is True


def test_scan_many_gated(tmp_path, monkeypatch, server):
    monkeypatch.setenv("HYDRA_AUTHORIZED_PROGRAMS", str(tmp_path / "empty.json"))
    g = BugBountyAuthorizationGate()
    res = AttackWorkflow(gate=g, executor=HttpExecutor(gate=g)).scan_many(
        [f"{server}/search?q=1"], "xss")
    assert res["confirmed"] is False
    assert all(s["authorized"] is False for s in res["scanned"])


# ── OOB poller + confirmer ───────────────────────────────────────────────────────
def test_oob_poller_correlates(server):
    oc = OOBCorrelator(ListenerConfig(oob_domain="oob.example"))
    tok = oc.mint("f1", "ssrf")
    poller = OOBPoller(f"{server}/poll?id={tok.token}", verify_tls=False).poll
    out = OOBConfirmer(oc, poller).confirm()
    assert out["count"] == 1 and out["confirmed_blind_findings"][0]["finding_id"] == "f1"


def test_oob_poller_defensive_on_bad_url():
    assert OOBPoller("http://127.0.0.1:9/nope", timeout=1).poll() == []
    assert OOBPoller("").poll() == []


# ── login flow ───────────────────────────────────────────────────────────────────
def test_login_flow_captures_session(gate, server):
    s = LoginFlow(gate=gate).login(f"{server}/login", {"user": "alice", "pass": "x"})
    assert s is not None
    assert s.cookies.get("session") == "ABC123"
    assert s.bearer == "jwt-xyz"
    assert s.authenticated is True


def test_login_flow_gated(tmp_path, monkeypatch, server):
    monkeypatch.setenv("HYDRA_AUTHORIZED_PROGRAMS", str(tmp_path / "empty.json"))
    g = BugBountyAuthorizationGate()
    assert LoginFlow(gate=g).login("http://example.com/login", {"u": "x"}) is None
