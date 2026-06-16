"""Race-condition tester (bounded concurrency through the gated executor)."""

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from hydra.attack_runtime import HttpExecutor, RaceTester
from hydra.authorization import BugBountyAuthorizationGate


class _App(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

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


def test_race_runs_bounded_concurrency(gate, server):
    rt = RaceTester(gate=gate, executor=HttpExecutor(gate=gate, rate_per_sec=0))
    out = rt.test({"method": "GET", "url": f"{server}/buy"}, n=8)
    assert out["authorized"] is True
    assert out["requests"] == 8 and out["executed"] == 8
    assert out["poc_only"] is True


def test_race_caps_count(gate, server):
    rt = RaceTester(gate=gate, executor=HttpExecutor(gate=gate, rate_per_sec=0))
    assert rt.test({"method": "GET", "url": f"{server}/x"}, n=999)["requests"] == 30   # hard cap


def test_race_deny_by_default(tmp_path, monkeypatch, server):
    monkeypatch.setenv("HYDRA_AUTHORIZED_PROGRAMS", str(tmp_path / "empty.json"))
    g = BugBountyAuthorizationGate()
    assert RaceTester(gate=g).test({"method": "GET", "url": "http://evil.example/x"})["authorized"] is False
