"""
Round-3 additions — live end-to-end through the gated HttpExecutor + a local server.

A local app simulates: a broken-access API object, a privileged function reachable by anyone, an OAuth
authorize endpoint that blindly honours redirect_uri, a gzip-compressed reflective endpoint, and a few
distinct query endpoints (for the concurrency/resume paths). Confirms the API/OAuth testers work over
real HTTP, that gzip is transparently decoded, that concurrent scanning matches sequential scanning,
and that everything stays deny-by-default.
"""

import gzip
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from hydra.attack import APIAttackTester, AttackWorkflow, OAuthTester
from hydra.attack.scan_state import ScanState
from hydra.attack_runtime import HttpExecutor, SessionContext
from hydra.authorization import BugBountyAuthorizationGate


class _App(BaseHTTPRequestHandler):
    def do_GET(self):
        p = urlparse(self.path)
        path, q = p.path, parse_qs(p.query)
        if path == "/api/doc/1":
            self._send(200, "owner:alice|secret-alice-data")          # broken object-level authz
        elif path == "/api/admin":
            self._send(200, "admin panel")                            # unguarded function
        elif path == "/authorize":
            self._redirect(q.get("redirect_uri", ["/"])[0])           # honours redirect_uri blindly
        elif path == "/gz":
            self._send_gzip(f"<html>echo {q.get('q', [''])[0]}</html>")
        elif path.startswith("/p"):
            self._send(200, f"<html>{path} {q.get('q', [''])[0]}</html>")
        else:
            self._send(404, "nope")

    def _send(self, code, body):
        b = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b)

    def _send_gzip(self, body):
        b = gzip.compress(body.encode())
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Encoding", "gzip")
        self.end_headers()
        self.wfile.write(b)

    def _redirect(self, loc):
        self.send_response(302)
        self.send_header("Location", loc)
        self.end_headers()

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


def test_bola_live(gate, server):
    ex = HttpExecutor(gate=gate, rate_per_sec=0)
    a = SessionContext("alice", cookies={"uid": "a"})
    b = SessionContext("bob", cookies={"uid": "b"})
    res = APIAttackTester(ex, gate=gate).bola(f"{server}/api/doc/1", a, b,
                                              owner_markers=["secret-alice-data"])
    assert res["confirmed"] is True


def test_bfla_live(gate, server):
    ex = HttpExecutor(gate=gate, rate_per_sec=0)
    res = APIAttackTester(ex, gate=gate).bfla(server, SessionContext("u"),
                                              functions=[("GET", "/api/admin")])
    assert res["confirmed"] is True


def test_oauth_redirect_uri_live(gate, server):
    ex = HttpExecutor(gate=gate, rate_per_sec=0)
    url = f"{server}/authorize?response_type=code&redirect_uri={server}/cb&state=s"
    res = OAuthTester(executor=ex, gate=gate).test_redirect_uri(url, evil="https://evil.example.com")
    assert res["confirmed"] is True
    assert any(r["strategy"] == "full_replace" for r in res["confirmed_findings"])


def test_gzip_is_transparently_decoded(gate, server):
    ex = HttpExecutor(gate=gate, rate_per_sec=0)
    resp = ex({"method": "GET", "url": f"{server}/gz?q=marker123", "headers": {},
               "payload": "marker123"})
    assert resp["executed"] and resp["reflected"] is True       # decoded, then reflection matched
    assert "echo marker123" in resp["body_snippet"]


def test_concurrent_scan_matches_sequential(gate, server):
    urls = [f"{server}/p{i}?q=hi" for i in range(6)]
    wf = AttackWorkflow(gate=gate, executor=HttpExecutor(gate=gate, rate_per_sec=0))
    seq = wf.scan_many(urls, "xss", context="html_body", concurrency=1)
    con = wf.scan_many(urls, "xss", context="html_body", concurrency=4)
    assert [s["target"] for s in seq["scanned"]] == [s["target"] for s in con["scanned"]]
    assert len(con["confirmed_findings"]) == len(seq["confirmed_findings"])
    assert con["concurrency"] == 4


def test_resume_skips_already_scanned(gate, server, tmp_path):
    st = ScanState(path=tmp_path / "state.jsonl")
    urls = [f"{server}/p{i}?q=hi" for i in range(3)]
    wf = AttackWorkflow(gate=gate, executor=HttpExecutor(gate=gate, rate_per_sec=0))
    first = wf.scan_many(urls, "xss", context="html_body", resume=True, state=st)
    assert first["skipped_already_scanned"] == []
    second = wf.scan_many(urls, "xss", context="html_body", resume=True, state=st)
    assert len(second["skipped_already_scanned"]) == len(first["scanned"])
    assert second["scanned"] == []
