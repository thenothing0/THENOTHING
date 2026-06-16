"""
Campaign orchestration (the capstone) — end-to-end through the gated executor.

A reflective server + DOM-stub gives a two-signal XSS; the campaign scans the class set, confirms,
matches chains, runs the (injected, isolated) loop-back, and produces a report — all in one gated call.
"""

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from hydra.attack import AttackCampaign, AttackWorkflow, FindingPublisher
from hydra.attack_runtime import HttpExecutor
from hydra.authorization import BugBountyAuthorizationGate


class _Reflect(BaseHTTPRequestHandler):
    def do_GET(self):
        q = parse_qs(urlparse(self.path).query)
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(f"<html>{q.get('q', [''])[0]}</html>".encode())

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def server():
    srv = HTTPServer(("127.0.0.1", 0), _Reflect)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


@pytest.fixture
def gate(tmp_path, monkeypatch):
    monkeypatch.setenv("HYDRA_AUTHORIZED_PROGRAMS", str(tmp_path / "p.json"))
    g = BugBountyAuthorizationGate()
    g.register_program("local", "custom", in_scope=["127.0.0.1"])
    return g


def test_campaign_end_to_end(gate, server):
    wf = AttackWorkflow(gate=gate, executor=HttpExecutor(gate=gate, rate_per_sec=0),
                        browser_confirmer=lambda url: {"confirmed": True})
    learns = []
    pub = FindingPublisher(save_fn=lambda *a: None,
                           verify_fn=lambda *a: (learns.append(a), True)[1])
    camp = AttackCampaign(wf, publisher=pub, classes=["xss"])
    res = camp.run(f"{server}/s?q=hi", confirm_dom=True, publish=True)

    assert res["authorized"] and res["poc_only"] is True
    assert res["confirmed"] >= 1 and res["per_class"]["xss"] >= 1        # two-signal confirmed
    assert res["published"]["learned_into_intelligence"] >= 1            # loop-back fired
    assert res["overall_severity"] in ("low", "medium", "high", "critical")
    assert res["report"]["confirmed_findings"][0]["cvss"]["score"] > 0   # report built
    assert len(learns) >= 1                                              # verification learning called


def test_campaign_deny_by_default(tmp_path, monkeypatch, server):
    monkeypatch.setenv("HYDRA_AUTHORIZED_PROGRAMS", str(tmp_path / "empty.json"))
    g = BugBountyAuthorizationGate()
    camp = AttackCampaign(AttackWorkflow(gate=g, executor=HttpExecutor(gate=g)))
    res = camp.run("http://evil.example/x")
    assert res["authorized"] is False
