"""
Active OOB blind-vuln tester (SSRF/XXE/cmdi) — injects OOB payloads, correlates callbacks.

A fake poller stands in for the operator's collaborator: it returns an interaction for every issued
token (simulating the target reaching the OOB server), so correlation confirms the blind finding.
"""

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from hydra.attack.oob import ListenerConfig, OOBCorrelator
from hydra.attack_runtime import HttpExecutor, OOBAttackTester
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


def test_ssrf_confirmed_via_oob_callback(gate, server):
    correlator = OOBCorrelator(ListenerConfig(oob_domain="oob.test"))

    def poller():                                          # simulate the target reaching our OOB server
        return [{"host": t["callback_host"], "protocol": "dns"} for t in correlator.issued()]

    tester = OOBAttackTester(gate=gate, executor=HttpExecutor(gate=gate, rate_per_sec=0),
                             correlator=correlator, poller=poller)
    res = tester.test(f"{server}/fetch?url=x", "ssrf", finding_id="f1")
    assert res["authorized"] and res["payloads_sent"] >= 1
    assert res["confirmed"] is True
    assert res["confirmed_blind_findings"][0]["finding_id"] == "f1"


def test_xxe_sends_external_entity_body(gate):
    bodies = []

    def executor(req):
        bodies.append(req.get("body", ""))
        return {"executed": True, "status": 200}

    tester = OOBAttackTester(gate=gate, executor=executor,
                             correlator=OOBCorrelator(ListenerConfig(oob_domain="oob.test")),
                             poller=lambda: [])
    res = tester.test("http://127.0.0.1/xxe", "xxe", finding_id="f2")
    assert res["payloads_sent"] >= 1
    assert any("ENTITY" in b for b in bodies)              # XXE external entity delivered as a body


def test_oob_deny_by_default(tmp_path, monkeypatch):
    monkeypatch.setenv("HYDRA_AUTHORIZED_PROGRAMS", str(tmp_path / "empty.json"))
    g = BugBountyAuthorizationGate()
    res = OOBAttackTester(gate=g, executor=lambda r: {}, poller=lambda: []).test(
        "http://evil.example/x", "ssrf")
    assert res["authorized"] is False


def test_oob_unknown_class(gate):
    res = OOBAttackTester(gate=gate, executor=lambda r: {"executed": True}, poller=lambda: []).test(
        "http://127.0.0.1/x", "not_a_class")
    assert "error" in res
