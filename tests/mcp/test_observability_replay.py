"""
Observability + Debug/Replay Harness (Pillars 7 & 8).

Pillar 8: proves the MCP boundary feeds the existing MetricsCollector
(tool execution count, failure count, latency histogram).
Pillar 7: proves RunRecorder captures a replayable run, that tool
executions are appended to the active run, and that replay reconstructs
the chain deterministically.
"""

import json

import mcp_server
from hydra.observability import MetricsCollector
from hydra.observability.run_recorder import RunRecorder, load_run, replay


# ── Pillar 8: metrics instrumentation ───────────────────────────────────

def test_run_increments_execution_metrics(monkeypatch):
    coll = MetricsCollector()
    monkeypatch.setattr(mcp_server, "_metrics", coll)
    mcp_server.subfinder_scan("example.com")  # resolves the fake, exits 0
    snap = coll.get_all()
    exec_keys = [k for k in snap["counters"] if k.startswith("tool_executions_total")]
    assert exec_keys, "tool execution counter not recorded"
    assert any("subfinder" in k for k in exec_keys)
    assert any(k.startswith("tool_latency_seconds") for k in snap["histograms"])


def test_failure_increments_failure_metric(monkeypatch):
    coll = MetricsCollector()
    monkeypatch.setattr(mcp_server, "_metrics", coll)
    # A binary that does not exist → _run returns failure → failure counter.
    mcp_server._run(["this-binary-does-not-exist-xyz"])
    snap = coll.get_all()
    assert any(k.startswith("tool_failures_total") for k in snap["counters"])


# ── Pillar 7: run recording + replay ────────────────────────────────────

def test_run_recorder_lifecycle(run_dir):
    rec = RunRecorder(target="example.com", workflow="quick_recon").start_run()
    rec.record_event("scope_check", {"allowed": True})
    rec.record_planner("quick_recon", [{"name": "subdomain_enum", "agent": "recon"}])
    path = rec.finish_run(result={"findings": 0}, status="completed")

    assert path.exists()
    data = load_run(rec.run_id, run_dir=run_dir)
    assert data["target"] == "example.com"
    assert data["status"] == "completed"
    kinds = [e["kind"] for e in data["events"]]
    assert "scope_check" in kinds and "planner" in kinds


def test_tool_events_appended_to_active_run(run_dir):
    rec = RunRecorder(target="example.com", workflow="recon").start_run()
    try:
        json.loads(mcp_server.subfinder_scan("example.com"))
        json.loads(mcp_server.whatweb_detect("https://example.com"))
    finally:
        rec.finish_run()

    events = replay(rec.run_id, run_dir=run_dir)
    tool_events = [e for e in events if e["kind"] == "tool_exec"]
    binaries = {e["data"]["binary"] for e in tool_events}
    assert "subfinder" in binaries
    assert "whatweb" in binaries
    # Replay is deterministic: re-reading yields the same ordered chain.
    assert [e["event_id"] for e in replay(rec.run_id, run_dir=run_dir)] == \
           [e["event_id"] for e in events]


def test_recorder_never_raises_without_active_run():
    # No active run env set → record_tool_event is a safe no-op.
    from hydra.observability.run_recorder import record_tool_event
    record_tool_event("subfinder", ["subfinder"], {"success": True})
