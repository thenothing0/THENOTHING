"""
Attack execution runtime tests — the real network boundary.

A local HTTP server stands in for an authorized target. Covers: the HttpExecutor is GATED
(deny-by-default, sends nothing for unauthorized hosts), actually sends + detects reflection for an
authorized host, observes redirects (open-redirect), rate-limits, and audits; the ScopeLoader
registers a program's scope into the gate; and the full AttackWorkflow runs end-to-end with a
confirmed verdict from a genuine reflective response.
"""

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from hydra.attack import AttackWorkflow
from hydra.attack_runtime import HttpExecutor, ScopeLoader
from hydra.authorization import BugBountyAuthorizationGate


class _Reflect(BaseHTTPRequestHandler):
    def do_GET(self):
        q = parse_qs(urlparse(self.path).query)
        if "redir" in q:                              # simulate an open redirect
            self.send_response(302)
            self.send_header("Location", q["redir"][0])
            self.end_headers()
            return
        raw = q.get("q", [""])[0]                      # reflect raw input (reflective sink)
        body = f"<html>you said: {raw}</html>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body)

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


# ── executor gating (defense-in-depth) ───────────────────────────────────────────
def test_executor_blocks_unauthorized_host(gate, server):
    ex = HttpExecutor(gate=gate)
    out = ex({"method": "GET", "url": "http://example.com/x", "payload": "x"})
    assert out["executed"] is False and out.get("blocked") is True
    assert ex.audit_log()[-1]["executed"] is False


def test_executor_sends_and_detects_reflection(gate, server):
    ex = HttpExecutor(gate=gate)
    out = ex({"method": "GET", "url": f"{server}/s?q=<poc-marker>", "payload": "<poc-marker>"})
    assert out["executed"] is True and out["status"] == 200
    assert out["reflected"] is True                    # raw payload echoed by the sink
    assert ex.audit_log()[-1]["executed"] is True


def test_executor_observes_redirect_without_following(gate, server):
    ex = HttpExecutor(gate=gate, allow_redirects=False)
    out = ex({"method": "GET", "url": f"{server}/r?redir=//evil.example.com", "payload": ""})
    assert out["status"] == 302
    assert out["location"] == "//evil.example.com"


def test_executor_rate_limited(gate, server):
    ex = HttpExecutor(gate=gate, rate_per_sec=5.0)     # ≥0.2s between requests
    t0 = time.time()
    for _ in range(3):
        ex({"method": "GET", "url": f"{server}/s?q=1", "payload": "1"})
    assert time.time() - t0 >= 0.4                     # 3 requests → ≥2 intervals of 0.2s


# ── scope loader ─────────────────────────────────────────────────────────────────
def test_scope_loader_registers_and_authorizes(tmp_path, monkeypatch):
    monkeypatch.setenv("HYDRA_AUTHORIZED_PROGRAMS", str(tmp_path / "p.json"))
    g = BugBountyAuthorizationGate()
    out = ScopeLoader(g).load_raw("custom", "acme",
                                  {"in_scope": [{"asset": "*.acme.com"}],
                                   "out_of_scope": [{"asset": "admin.acme.com"}]})
    assert out["registered"]["program"] and out["in_scope_assets"] == 1
    assert g.authorize("https://api.acme.com", "exploitation").authorized is True
    assert g.authorize("https://admin.acme.com", "exploitation").authorized is False


# ── full workflow end-to-end (real send, real verdict) ───────────────────────────
def test_workflow_live_confirmed_via_reflection(gate, server):
    ex = HttpExecutor(gate=gate)
    r = AttackWorkflow(gate=gate, executor=ex).run(f"{server}/search", "xss",
                                                   context="html_body", execute=True)
    assert r.authorized and r.executed and r.poc_only
    assert r.evidence["verdict"] == "confirmed"        # payload genuinely reflected
    assert r.evidence["curl"].startswith("curl")


def test_workflow_unauthorized_sends_nothing(gate, server):
    calls = []
    ex = HttpExecutor(gate=gate)
    orig = ex.__call__

    def spy(req):
        calls.append(req)
        return orig(req)

    ex.__call__ = spy  # type: ignore
    r = AttackWorkflow(gate=gate, executor=ex).run("http://evil.example.com", "xss", execute=True)
    assert r.authorized is False and r.executed is False
    assert calls == []                                 # gate stops it before the executor


def test_workflow_serializable(gate, server):
    r = AttackWorkflow(gate=gate, executor=HttpExecutor(gate=gate)).run(
        f"{server}/s", "ssti", context="any", execute=True)
    json.dumps(r.to_dict())
