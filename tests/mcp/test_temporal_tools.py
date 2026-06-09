"""Phase O MCP behavior: temporal tools read-only/deterministic/advisory, no wiki mutation,
promotion/confidence untouched, contract reaches 108 tools."""

import asyncio
import json
import sqlite3

import pytest

import hydra.knowledge.confidence as confidence_mod
import mcp_server
from tests.knowledge.conftest import build_seed

DAY = 86_400.0
WINDOW = 30
NOW = 200 * DAY


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("HYDRA_WIKI_DIR", str(tmp_path / "wiki"))
    monkeypatch.setenv("HYDRA_TOOL_HEALTH_DB", str(tmp_path / "th.db"))
    monkeypatch.setenv("HYDRA_TEMPORAL_DB", str(tmp_path / "t.db"))
    build_seed(tmp_path / "wiki")


def _seed(cap="cap_rise"):
    from hydra.adapters.tool_health import ToolHealthStore
    import os
    ToolHealthStore()
    con = sqlite3.connect(os.environ["HYDRA_TOOL_HEALTH_DB"])
    for b in range(20, 30):
        for i in range(2 * (b - 19)):
            ts = NOW - (WINDOW - 1 - b) * DAY
            con.execute("INSERT OR IGNORE INTO health_events(adapter_id,capability_id,category,"
                        "event_type,outcome,runtime_ms,dedup_key,occurred_at) VALUES (?,?,?,?,?,?,?,?)",
                        (f"{cap}::t1", cap, "web", "execution", "success", 1.0, f"{cap}{b}{i}", ts))
    con.commit()
    con.close()


def _by_type():
    return json.loads(mcp_server.kb_lint())["stats"]["by_type"]


def test_mcp_count_at_least_108():
    # Phase O brought the registry to 108; later phases only add (exact count is pinned by the
    # contract baseline in test_tool_contract.py). Here we assert the temporal tools are present.
    live = {t.name for t in asyncio.run(mcp_server.mcp.list_tools())}
    assert len(live) >= 108
    for t in ("temporal_summary", "temporal_trends", "temporal_forecast",
              "temporal_decay", "temporal_anomalies", "temporal_health"):
        assert t in live


def test_temporal_tools_run_and_are_deterministic():
    _seed()
    a = json.loads(mcp_server.temporal_summary(now=NOW))
    b = json.loads(mcp_server.temporal_summary(now=NOW))
    assert a == b and a["advisory"] is True
    tr = json.loads(mcp_server.temporal_trends(domain="capability", now=NOW))
    assert any(t["entity"] == "cap_rise" and t["direction"] == "rising" for t in tr["trends"])
    fc = json.loads(mcp_server.temporal_forecast(domain="capability", now=NOW))
    assert fc["domain_forecast"]["slope"] > 0
    assert "decay_findings" in json.loads(mcp_server.temporal_decay(now=NOW))
    assert "anomalies" in json.loads(mcp_server.temporal_anomalies(now=NOW))
    assert "temporal_health_score" in json.loads(mcp_server.temporal_health(now=NOW))


def test_temporal_tools_never_mutate_wiki():
    _seed()
    before = _by_type()
    mcp_server.temporal_summary(now=NOW)
    mcp_server.temporal_trends(now=NOW)
    mcp_server.temporal_forecast(now=NOW)
    mcp_server.temporal_decay(now=NOW)
    mcp_server.temporal_anomalies(now=NOW)
    mcp_server.temporal_health(now=NOW)
    assert _by_type() == before, "Phase-O temporal tools must not mutate the wiki"


def test_governance_summary_exposes_temporal_block():
    out = json.loads(mcp_server.governance_summary())
    assert "temporal_intelligence" in out


def test_confidence_module_unchanged():
    _seed()
    assert confidence_mod.score_from_sources(["a", "b"], {"a": 0.7, "b": 0.7}).value == "high"
    assert confidence_mod.score_from_sources(["a"]).value == "low"
