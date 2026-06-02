"""
Shared pytest fixtures for the THENOTHING harness.

Design (per harness plan):
  * Unit / contract / behavior / workflow / eval tests run OFFLINE with no
    Kali tools and no network:
      - `fake_tools` (autouse) prepends tests/_doubles/bin to PATH so the REAL
        mcp_server._run() subprocess pipeline resolves deterministic fakes.
        This exercises shell=False, argv construction and output parsing for
        real — it does NOT monkeypatch _run (no coverage inflation).
      - `mock_providers` (autouse) blocks accidental LLM network calls.
  * Integration / e2e tests are EXEMPT from the fakes (they want real tools)
    and are deselected by default (see pyproject markers).
"""

import os
import sys
from pathlib import Path

import pytest

# Make the repo root importable (mcp_server lives there).
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests._doubles import BIN_DIR  # noqa: E402


def _is_real_tool_test(request) -> bool:
    return bool(
        request.node.get_closest_marker("integration")
        or request.node.get_closest_marker("e2e")
    )


@pytest.fixture(autouse=True)
def fake_tools(request, monkeypatch):
    """Put fake security binaries on PATH for all offline tests.

    Skipped for integration/e2e tests, which must resolve the real binaries.
    """
    if _is_real_tool_test(request):
        yield None
        return
    monkeypatch.setenv("PATH", f"{BIN_DIR}{os.pathsep}{os.environ.get('PATH', '')}")
    # Ensure Tor wrapping is off during tests regardless of the dev's shell.
    monkeypatch.setenv("HYDRA_TOR", "0")
    yield BIN_DIR


@pytest.fixture(autouse=True)
def mock_providers(request, monkeypatch):
    """Prevent accidental LLM/network calls in offline tests.

    Sets dummy keys and, if the SDKs are importable, replaces their network
    entrypoints with a guard that fails loudly rather than hitting the wire.
    """
    if _is_real_tool_test(request):
        yield
        return
    monkeypatch.setenv("OPENAI_API_KEY", "test-dummy")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-dummy")

    def _no_network(*_a, **_k):  # pragma: no cover - only fires on misuse
        raise RuntimeError(
            "Network/LLM call attempted during an offline test. "
            "Mock the provider explicitly in the test."
        )

    for mod_name, attr_path in (("openai", "OpenAI"), ("anthropic", "Anthropic")):
        try:
            mod = __import__(mod_name)
            if hasattr(mod, attr_path):
                monkeypatch.setattr(f"{mod_name}.{attr_path}", _no_network, raising=False)
        except Exception:
            pass
    yield


@pytest.fixture
def run_dir(tmp_path, monkeypatch):
    """Isolated output/runs directory for RunRecorder tests."""
    d = tmp_path / "runs"
    d.mkdir()
    monkeypatch.setenv("HYDRA_RUN_DIR", str(d))
    return d
