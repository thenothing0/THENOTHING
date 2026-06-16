"""
Live scan + access-control + chain execution (end-to-end through the gated HttpExecutor).

A local server simulates a reflective XSS sink, a broken-access-control endpoint (returns the same
resource to everyone), and a properly-secured one (403 for non-owners). Confirms that the differential
scan finds reflective XSS, that the dual-session test flags the IDOR but not the secured endpoint, and
that everything stays deny-by-default.
"""

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from hydra.attack import AttackWorkflow
from hydra.attack_runtime import HttpExecutor, SessionManager
from hydra.authorization import BugBountyAuthorizationGate


class _App(BaseHTTPRequestHandler):
    def _uid(self):
        for c in (self.headers.get("Cookie", "") or "").split("; "):
            if c.startswith("uid="):
                return c[4:]
        return ""

    def do_GET(self):
        path = urlparse(self.path).path
        q = parse_qs(urlparse(self.path).query)
        if path == "/search":
            raw = q.get("q", [""])[0]
            self._send(200, f"<html>results for {raw}</html>")          # reflective sink
        elif path == "/vuln-doc":
            self._send(200, "owner:alice|secret-alice-data")            # broken access control
        elif path == "/safe-doc":
            if self._uid() == "alice":
                self._send(200, "owner:alice|secret-alice-data")
            else:
                self._send(403, "forbidden")
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
def wf(tmp_path, monkeypatch):
    monkeypatch.setenv("HYDRA_AUTHORIZED_PROGRAMS", str(tmp_path / "p.json"))
    g = BugBountyAuthorizationGate()
    g.register_program("local", "custom", in_scope=["127.0.0.1"])
    return AttackWorkflow(gate=g, executor=HttpExecutor(gate=g, rate_per_sec=0))


def test_scan_confirms_reflective_xss(wf, server):
    res = wf.scan(f"{server}/search?q=hi", "xss", context="html_body")
    assert res["authorized"] and res["executed"] and res["confirmed"] is True
    assert res["confirmed_findings"][0]["evidence"]["verdict"] == "confirmed"
    assert res["points_tested"] >= 1


def test_scan_deny_by_default(tmp_path, monkeypatch, server):
    monkeypatch.setenv("HYDRA_AUTHORIZED_PROGRAMS", str(tmp_path / "empty.json"))
    g = BugBountyAuthorizationGate()
    res = AttackWorkflow(gate=g, executor=HttpExecutor(gate=g)).scan(f"{server}/search", "xss")
    assert res["authorized"] is False and res["confirmed"] is False and res["evidence"] == []


def test_access_control_flags_idor(wf, server):
    sm = SessionManager()
    alice = sm.add("alice", cookies={"uid": "alice"})
    bob = sm.add("bob", cookies={"uid": "bob"})
    res = wf.access_control_test(f"{server}/vuln-doc", alice, bob,
                                 owner_markers=["secret-alice-data"])
    assert res["verdict"] == "confirmed"          # bob received alice's resource


def test_access_control_passes_secured_endpoint(wf, server):
    sm = SessionManager()
    alice = sm.add("alice", cookies={"uid": "alice"})
    bob = sm.add("bob", cookies={"uid": "bob"})
    res = wf.access_control_test(f"{server}/safe-doc", alice, bob,
                                 owner_markers=["secret-alice-data"])
    assert res["verdict"] == "refuted"            # bob properly denied (403)


def test_chain_execute_gated_and_redacted(wf, server):
    from hydra.attack import ChainExecutor
    res = ChainExecutor(wf).execute(f"{server}/x", "ssrf_imds_takeover")
    assert res["total_stages"] == 3
    assert 0 <= res["demonstrated_depth"] <= 3
    assert "redacted" in res["note"].lower()
