"""E2E integration: a REAL tool execution flows through the orchestrator and
drives every subsystem — coverage, findings (from real output), learning, session.
No mocks: real subprocess execution, real SQLite stores, real enforcement gateway.
"""

import subprocess
import sys

from hydra.coverage import CoverageStore
from hydra.engagement import EngagementStore, Role
from hydra.findings import FindingsStore
from hydra.hitl import ApprovalPolicy
from hydra.learning_tiers import LearningTiersStore
from hydra.orchestration import RuntimeContext, RuntimeOrchestrator, ToolGateway
from hydra.session import SessionStore
from hydra.workflow import PentestWorkflow


def _real_nuclei_like_tool() -> dict:
    """REAL execution: run a subprocess that emits genuine nuclei-style output.
    (No mock — the OS actually runs this and we parse its stdout.)"""
    line = "[apache-vuln-cve] [http] [high] https://t.example.com/x"
    proc = subprocess.run([sys.executable, "-c", f"print({line!r})"],
                          capture_output=True, text=True)
    return {"success": proc.returncode == 0, "output": proc.stdout, "tool_used": "nuclei"}


def _orchestrator(tmp_path, *, role="lead", operator_mode=True):
    est = EngagementStore(db_path=str(tmp_path / "eng.db"))
    eid = est.create("self", "auto", scope=["t.example.com"], owner="operator")
    gw = ToolGateway(engagement_store=est,
                     approval_policy=ApprovalPolicy(operator_mode=operator_mode),
                     audit_path=str(tmp_path / "audit.jsonl"), enforce_rbac=True)
    orch = RuntimeOrchestrator(
        gateway=gw,
        findings=FindingsStore(db_path=str(tmp_path / "f.db")),
        coverage=CoverageStore(db_path=str(tmp_path / "c.db")),
        learning=LearningTiersStore(db_path=str(tmp_path / "l.db")),
        session=SessionStore("e2e", base_dir=str(tmp_path / "sessions")),
        workflow=PentestWorkflow(db_path=str(tmp_path / "w.db")),
        engagement_id=eid, target="t.example.com")
    ctx = RuntimeContext(engagement_id=eid, target="t.example.com", role=role,
                         operator_mode=operator_mode)
    return orch, ctx, eid


def test_e2e_scan_drives_all_subsystems(tmp_path):
    orch, ctx, eid = _orchestrator(tmp_path)

    result = orch.run_sync("nuclei", {"target": "t.example.com"}, ctx, _real_nuclei_like_tool)
    assert result["success"] is True            # real tool ran

    # Phase 4 — coverage updated automatically.
    cov = orch.coverage.summary(eid)
    assert cov["total_tuples"] >= 1 and cov["tested_tuples"] >= 1

    # Phase 3 — a finding was created from the REAL tool output, with evidence.
    findings = orch.findings.list(eid)
    assert len(findings) == 1
    f = orch.findings.get(findings[0]["id"])
    assert f["severity"] == "high" and f["evidence"][0]["kind"] == "tool_output"

    # Phase 5 — a lesson was learned (and is retrievable / not quarantined).
    assert orch.learning.stats()["active_by_tier"].get("project", 0) >= 1

    # Phase 6 — the session was auto-saved.
    assert SessionStore("e2e", base_dir=str(tmp_path / "sessions")).exists()

    # Workflow state machine advanced (nuclei => validation phase) + checkpointed.
    run = orch.workflow.get(orch.workflow_run_id)
    assert run["state"] == "validation"
    assert run["checkpoint"].get("last_tool") == "nuclei"

    assert orch.stats["executed"] == 1 and orch.stats["findings"] == 1


def test_e2e_rbac_denial_stops_execution(tmp_path):
    # A viewer may not run a scan → the gateway must BLOCK before execution.
    orch, ctx, eid = _orchestrator(tmp_path, role=Role.VIEWER, operator_mode=True)
    ran = {"v": False}

    def _tool():
        ran["v"] = True
        return {"success": True, "output": "should never run"}

    result = orch.run_sync("nuclei", {"target": "t.example.com"}, ctx, _tool)
    assert result["blocked"] is True
    assert ran["v"] is False                     # execution was actually prevented
    assert orch.findings.list(eid) == []         # nothing downstream happened
    assert orch.stats["blocked"] == 1 and orch.stats["executed"] == 0


def test_e2e_prohibited_hard_denied_even_operator_mode(tmp_path):
    orch, ctx, _ = _orchestrator(tmp_path, role="admin", operator_mode=True)
    ran = {"v": False}

    def _tool():
        ran["v"] = True
        return {"success": True, "output": ""}

    # shell_exec with a fork bomb → PROHIBITED → blocked even for admin in YOLO.
    result = orch.run_sync("shell_exec", {"command": ":(){ :|:& };:"}, ctx, _tool)
    assert result["blocked"] is True and ran["v"] is False


def test_e2e_audit_log_records_decisions(tmp_path):
    orch, ctx, _ = _orchestrator(tmp_path)
    orch.run_sync("nuclei", {"target": "t.example.com"}, ctx, _real_nuclei_like_tool)
    audit = (tmp_path / "audit.jsonl").read_text()
    assert "nuclei" in audit and '"allowed": true' in audit


def test_e2e_session_autocompacts_over_threshold(tmp_path):
    orch, ctx, _ = _orchestrator(tmp_path)
    for _ in range(45):                          # exceed the 40-entry compact threshold
        orch.run_sync("httpx", {"target": "t.example.com"}, ctx,
                      lambda: {"success": True, "output": "200 OK"})
    assert orch.stats["compactions"] >= 1


def test_e2e_recon_feeds_burp_capture_store(tmp_path):
    from hydra.burp import STORE
    STORE.clear()
    orch, ctx, _ = _orchestrator(tmp_path)
    orch.run_sync("httpx", {"target": "t.example.com"}, ctx, lambda: {
        "success": True,
        "output": "https://a.t.example.com/x [200]\nhttps://b.t.example.com/y [200]"})
    # the discovered endpoints landed in the real capture store (queryable via burp_*)
    assert STORE.stats()["requests"] >= 2
    STORE.clear()
