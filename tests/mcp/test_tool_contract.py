"""
MCP Contract Harness (Pillar 2) — mitigates Risk #5 (tool-registry drift).

The last commit before this harness existed was a fix for tool-name casing
drift (gxss) and an incomplete `check_tools`. Nothing guarded against it
happening again. These tests pin the live MCP registry against:

  1. a committed schema baseline (names + parameters + required args), so any
     rename / removed-tool / changed-required-param fails CI with a clear diff;
  2. CLAUDE.md's documented "MCP tool palette", so code and docs cannot drift
     apart silently.

If a contract change is intentional, regenerate the baseline deliberately
(see REGEN note below) — that makes the change explicit in code review.
"""

import asyncio
import json
import re
from pathlib import Path

import pytest

import mcp_server

ROOT = Path(__file__).resolve().parents[2]
BASELINE_PATH = Path(__file__).resolve().parent / "tool_contract_baseline.json"
CLAUDE_MD = ROOT / "CLAUDE.md"

# REGEN: python -c "import asyncio,json;import mcp_server as m;\
#   t=asyncio.run(m.mcp.list_tools());\
#   print(json.dumps({x.name:{'required':sorted((x.inputSchema or {}).get('required',[])),\
#   'params':sorted(((x.inputSchema or {}).get('properties') or {}).keys())} for x in t},indent=2))"


def _live_registry():
    tools = asyncio.run(mcp_server.mcp.list_tools())
    out = {}
    for t in tools:
        schema = t.inputSchema or {}
        out[t.name] = {
            "required": sorted(schema.get("required", [])),
            "params": sorted((schema.get("properties") or {}).keys()),
        }
    return out


def _baseline():
    return json.loads(BASELINE_PATH.read_text())


def test_baseline_file_exists():
    assert BASELINE_PATH.exists(), "tool_contract_baseline.json missing — regenerate it"


def test_registry_tool_names_match_baseline():
    live = set(_live_registry())
    expected = set(_baseline())
    added = live - expected
    removed = expected - live
    assert not added, f"Undocumented/new MCP tools (update baseline + CLAUDE.md): {sorted(added)}"
    assert not removed, f"MCP tools missing from registry (regression?): {sorted(removed)}"


def test_registry_schemas_match_baseline():
    live = _live_registry()
    base = _baseline()
    for name, spec in base.items():
        assert live[name]["params"] == spec["params"], (
            f"Parameter drift in '{name}': {live[name]['params']} != {spec['params']}"
        )
        assert live[name]["required"] == spec["required"], (
            f"Required-arg drift in '{name}': {live[name]['required']} != {spec['required']}"
        )


def test_every_tool_is_documented_in_claude_md():
    """Every registered tool name must appear in CLAUDE.md (docs vs code)."""
    doc = CLAUDE_MD.read_text(encoding="utf-8")
    # Tool names are referenced in CLAUDE.md as `tool_name` in the palette.
    documented = set(re.findall(r"`([a-z0-9_]+)`", doc))
    live = set(_live_registry())
    undocumented = live - documented
    assert not undocumented, (
        f"Tools registered but not documented in CLAUDE.md: {sorted(undocumented)}"
    )


@pytest.mark.parametrize("expected_tool", [
    "subfinder_scan", "httpx_probe", "nuclei_scan", "sqlmap_scan",
    "ffuf_fuzz", "gxss_check", "check_tools", "generate_report",
])
def test_known_critical_tools_registered(expected_tool):
    assert expected_tool in _live_registry()
