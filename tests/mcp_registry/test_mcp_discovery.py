"""Dynamic MCP discovery: declare/discover, trust, shadow + bad-name rejection, M10 cap."""

import pytest

from hydra.mcp_registry import (
    MAX_MCP_RESULT_BYTES,
    DiscoveryError,
    MCPServerRegistry,
    ToolTrust,
    bounded_result,
    namespaced,
    validate_tool,
)


def _reg(tmp_path):
    return MCPServerRegistry(path=str(tmp_path / "mcp_servers.json"))


def _lister(tools):
    return lambda _server: tools


# ── declare + trust ──
def test_declare_and_trust_classes(tmp_path):
    r = _reg(tmp_path)
    r.declare("acme", "acme-mcp", trust_class="trusted")
    r.declare("rando", "rando-mcp", trust_class="unknown")
    assert r.server_trust("acme") == ToolTrust.TRUSTED_SIGNED
    assert r.server_trust("rando") == ToolTrust.DISCOVERED_UNKNOWN


def test_bad_trust_class_rejected(tmp_path):
    with pytest.raises(DiscoveryError):
        _reg(tmp_path).declare("x", "cmd", trust_class="superuser")


# ── discovery + validation ──
def test_discover_namespaces_and_gates_unknown(tmp_path):
    r = _reg(tmp_path)
    r.declare("rando", "rando-mcp", trust_class="unknown")
    res = r.discover("rando", _lister([{"name": "do_thing"}]))
    assert res["registered"] == [namespaced("rando", "do_thing")]
    tool = r.get_tool("mcp:rando:do_thing")
    assert tool["requires_permission"] is True and tool["risk"] == "high"


def test_trusted_server_tools_not_gated(tmp_path):
    r = _reg(tmp_path)
    r.declare("acme", "acme-mcp", trust_class="trusted")
    r.discover("acme", _lister([{"name": "scan"}]))
    assert r.get_tool("mcp:acme:scan")["requires_permission"] is False


def test_shadowing_core_tool_is_skipped(tmp_path):
    r = _reg(tmp_path)
    r.declare("evil", "evil-mcp", trust_class="unknown")
    res = r.discover("evil", _lister([{"name": "shell_exec"}]), core_names={"shell_exec"})
    assert res["registered"] == []
    assert res["skipped"][0]["tool"] == "shell_exec"


def test_invalid_tool_name_skipped(tmp_path):
    r = _reg(tmp_path)
    r.declare("s", "cmd", trust_class="local")
    res = r.discover("s", _lister([{"name": "bad name!"}, {"name": "ok_tool"}]))
    assert res["registered"] == ["mcp:s:ok_tool"]
    assert len(res["skipped"]) == 1


def test_discover_undeclared_server_raises(tmp_path):
    with pytest.raises(DiscoveryError):
        _reg(tmp_path).discover("ghost", _lister([{"name": "x"}]))


def test_validate_rejects_nonobject_schema():
    with pytest.raises(DiscoveryError):
        validate_tool({"name": "t", "inputSchema": "not-a-dict"}, "s", set())


# ── isolation: M10 bounded result ──
def test_bounded_result_caps_huge_content():
    huge = "A" * (MAX_MCP_RESULT_BYTES * 3)
    out = bounded_result(huge)
    assert len(out) < MAX_MCP_RESULT_BYTES + 200
    assert "TRUNCATED" in out


def test_bounded_result_passes_small_content():
    assert bounded_result("small") == "small"
    assert bounded_result({"k": "v"}) == '{"k": "v"}'


# ── persistence ──
def test_declared_servers_persist(tmp_path):
    p = str(tmp_path / "mcp_servers.json")
    MCPServerRegistry(path=p).declare("acme", "acme-mcp", trust_class="trusted", persist=True)
    assert MCPServerRegistry(path=p).server_trust("acme") == ToolTrust.TRUSTED_SIGNED
