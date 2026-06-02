"""
Real-Tool Integration Harness (hybrid strategy).

The platform DEPENDS on real Kali binaries in production, so the toolchain
must be verifiable for real — but never as part of standard CI. These tests:

  * are marked `integration` and therefore DESELECTED by the default
    pytest run (see pyproject `addopts`);
  * additionally require an explicit opt-in env flag HYDRA_RUN_INTEGRATION=1;
  * SKIP individually when a given binary is not installed.

The `fake_tools` / `mock_providers` autouse fixtures are disabled for
integration tests (see conftest), so these resolve the REAL binaries on PATH.

Run on a Kali box with:
    HYDRA_RUN_INTEGRATION=1 pytest -m integration
Optionally target your own authorized host:
    HYDRA_RUN_INTEGRATION=1 HYDRA_TEST_TARGET=scanme.nmap.org pytest -m integration
"""

import json
import os
import shutil

import pytest

import mcp_server

pytestmark = pytest.mark.integration

_ENABLED = os.environ.get("HYDRA_RUN_INTEGRATION") == "1"
_TARGET = os.environ.get("HYDRA_TEST_TARGET", "example.com")
_URL = _TARGET if "://" in _TARGET else f"https://{_TARGET}"

skip_unless_enabled = pytest.mark.skipif(
    not _ENABLED, reason="set HYDRA_RUN_INTEGRATION=1 to run real-tool tests")


def _require(binary: str):
    if shutil.which(binary) is None:
        pytest.skip(f"{binary} not installed")


@skip_unless_enabled
def test_check_tools_reports_real_environment():
    res = json.loads(mcp_server.check_tools())
    # Honest report of the real box — at least the structure must hold.
    assert "available" in res and "total" in res
    assert res["total"] >= 16


@skip_unless_enabled
def test_real_subfinder():
    _require("subfinder")
    res = json.loads(mcp_server.subfinder_scan(_TARGET))
    assert "subdomains" in res or res.get("success") is False


@skip_unless_enabled
def test_real_httpx():
    _require("httpx")
    res = json.loads(mcp_server.httpx_probe(_TARGET))
    assert "output" in res


@skip_unless_enabled
def test_real_whatweb():
    _require("whatweb")
    res = json.loads(mcp_server.whatweb_detect(_URL))
    assert "output" in res


@skip_unless_enabled
def test_real_nuclei_runs():
    _require("nuclei")
    res = json.loads(mcp_server.nuclei_scan(_URL, severity="info"))
    # We only assert it executed and returned a structured result.
    assert "findings" in res or "error" in res


@skip_unless_enabled
def test_real_tool_validation_still_enforced():
    """Even with real tools present, the boundary must reject injection."""
    res = json.loads(mcp_server.nmap_scan("--script=http-evil"))
    assert res.get("rejected") is True
