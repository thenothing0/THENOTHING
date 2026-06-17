"""
Round-4 additions — live end-to-end through the gated HttpExecutor + a local server.

A tiny app simulates a STORED sink (POST /save persists a value, GET /show reflects it) and an endpoint
with a hidden `debug` parameter (reflected only when present). Confirms stored-XSS persistence is
detected across endpoints, that parameter mining finds the hidden param over real HTTP, and that both
stay deny-by-default.
"""

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from hydra.attack import ParameterMiner, StoredVulnTester
from hydra.attack_runtime import HttpExecutor
from hydra.authorization import BugBountyAuthorizationGate

_STORE = {"v": ""}


class _App(BaseHTTPRequestHandler):
    def do_GET(self):
        p = urlparse(self.path)
        q = parse_qs(p.query)
        if p.path == "/show":
            self._send(200, f"<html>{_STORE['v']}</html>")
        elif p.path == "/hidden":
            self._send(200, f"echo {q['debug'][0]}" if "debug" in q else "nothing")
        else:
            self._send(404, "nope")

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n).decode()
        _STORE["v"] = parse_qs(body).get("bio", [""])[0]      # persist submitted value
        self._send(200, "saved")

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


def test_stored_persistence_detected_live(gate, server):
    ex = HttpExecutor(gate=gate, rate_per_sec=0)
    tester = StoredVulnTester(gate=gate, executor=ex,
                              browser_confirmer=lambda url: {"confirmed": True})
    submit = {"method": "POST", "url": f"{server}/save",
              "headers": {"Content-Type": "application/x-www-form-urlencoded"},
              "body": "bio=seed"}
    res = tester.test(submit, [f"{server}/show"], vuln_class="xss", field="bio")
    assert res["persisted"] is True and res["confirmed"] is True


def test_param_mining_live(gate, server):
    ex = HttpExecutor(gate=gate, rate_per_sec=0)
    res = ParameterMiner(gate=gate, executor=ex).mine(
        f"{server}/hidden", wordlist=["foo", "debug", "bar"], batch=10)
    assert any(d["param"] == "debug" for d in res["discovered"])


def test_stored_deny_by_default(tmp_path, monkeypatch, server):
    monkeypatch.setenv("HYDRA_AUTHORIZED_PROGRAMS", str(tmp_path / "empty.json"))
    g = BugBountyAuthorizationGate()
    res = StoredVulnTester(gate=g, executor=HttpExecutor(gate=g)).test(
        {"method": "POST", "url": f"{server}/save", "body": "bio=x"}, [f"{server}/show"])
    assert res["authorized"] is False
