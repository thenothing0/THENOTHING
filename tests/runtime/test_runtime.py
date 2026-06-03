"""Phase I — execution runtime: deterministic ids, state machine, retry, rebuild-identical."""

import pytest

from hydra.runtime.engine import RuntimeEngine, RuntimeIntelligence
from hydra.runtime.workflows import (
    RetryPolicy,
    TaskState,
    WorkflowState,
    WorkflowStateError,
    WorkflowStore,
    validate_task_transition,
    validate_workflow_transition,
)


def _engine(tmp_path, tag="w", **kw):
    return RuntimeEngine(store=WorkflowStore(tmp_path / f"{tag}.db"), now=1000.0, **kw)


# ── deterministic ids ─────────────────────────────────────────────────────────
def test_workflow_id_deterministic(tmp_path):
    a = _engine(tmp_path, "a").create_workflow("acme.com", "api", 1)
    b = _engine(tmp_path, "b").create_workflow("acme.com", "api", 1)
    assert a == b and a.startswith("wf-")


def test_workflow_create_idempotent(tmp_path):
    eng = _engine(tmp_path)
    wf1 = eng.create_workflow("acme.com", "web")
    n1 = len(eng.workflow_status(wf1)["tasks"])
    wf2 = eng.create_workflow("acme.com", "web")  # same plan → same id, no dup
    assert wf1 == wf2
    assert len(eng.workflow_status(wf2)["tasks"]) == n1


def test_task_ids_deterministic_and_tool_independent(tmp_path):
    # ids derive from agent:capability, not the learning-selected tool
    a = {t["task_id"] for t in _engine(tmp_path, "a").workflow_status(
        _engine(tmp_path, "a").create_workflow("acme.com", "web")).get("tasks", [])}
    eng = _engine(tmp_path, "b")
    wf = eng.create_workflow("acme.com", "web")
    b = {t["task_id"] for t in eng.workflow_status(wf)["tasks"]}
    assert a == b and all(t.startswith("task-") for t in b)


# ── state machine ─────────────────────────────────────────────────────────────
def test_valid_lifecycle_completes(tmp_path):
    eng = _engine(tmp_path)
    wf = eng.create_workflow("acme.com", "web")
    assert eng.workflow_status(wf)["workflow"]["status"] == "PENDING"
    eng.start_workflow(wf)
    for _ in range(500):
        r = eng.advance_workflow(wf, "completed")
        if r.get("workflow_status") in ("COMPLETED", "FAILED"):
            break
    assert eng.workflow_status(wf)["workflow"]["status"] == "COMPLETED"


def test_invalid_workflow_transition_raises():
    with pytest.raises(WorkflowStateError):
        validate_workflow_transition(WorkflowState.COMPLETED, WorkflowState.RUNNING)


def test_invalid_task_transition_raises():
    with pytest.raises(WorkflowStateError):
        validate_task_transition(TaskState.COMPLETED, TaskState.RUNNING)


def test_advance_requires_running(tmp_path):
    eng = _engine(tmp_path)
    wf = eng.create_workflow("acme.com", "web")
    with pytest.raises(WorkflowStateError):       # not started yet
        eng.advance_workflow(wf, "completed")


def test_cancel_from_running(tmp_path):
    eng = _engine(tmp_path)
    wf = eng.create_workflow("acme.com", "web")
    eng.start_workflow(wf)
    eng.cancel_workflow(wf)
    assert eng.workflow_status(wf)["workflow"]["status"] == "CANCELLED"
    with pytest.raises(WorkflowStateError):       # cannot advance a cancelled workflow
        eng.advance_workflow(wf, "completed")


# ── retry policy ──────────────────────────────────────────────────────────────
def test_retry_policy_enforced(tmp_path):
    eng = _engine(tmp_path, retry_policy=RetryPolicy(max_retries=2))
    wf = eng.create_workflow("x.com", "web")
    eng.start_workflow(wf)
    r1 = eng.advance_workflow(wf, "failed", "boom")
    r2 = eng.advance_workflow(wf, "failed", "boom")
    r3 = eng.advance_workflow(wf, "failed", "boom")
    assert r1["task_status"] == "RETRYING" and r1["attempts"] == 1
    assert r1["backoff_seconds"] == 5.0
    assert r2["task_status"] == "RETRYING" and r2["attempts"] == 2
    assert r3["task_status"] == "FAILED" and r3["attempts"] == 3   # terminal after max_retries


def test_workflow_fails_when_task_terminal_fails(tmp_path):
    # a workflow with a single actionable task that fails terminally → FAILED
    eng = _engine(tmp_path, retry_policy=RetryPolicy(max_retries=0))
    wf = eng.create_workflow("x.com", "mobile")   # mobile → fewer tool tasks
    eng.start_workflow(wf)
    # fail every task terminally
    for _ in range(500):
        r = eng.advance_workflow(wf, "failed", "boom")
        if r.get("workflow_status") in ("COMPLETED", "FAILED"):
            break
    assert eng.workflow_status(wf)["workflow"]["status"] == "FAILED"


# ── rebuild-identical ─────────────────────────────────────────────────────────
def _strip(rows):
    out = []
    for r in rows:
        d = {k: v for k, v in r.items() if k not in ("started_at", "completed_at")}
        out.append(d)
    return out


def test_rebuild_identical_runtime(tmp_path):
    def run(tag):
        eng = _engine(tmp_path, tag, retry_policy=RetryPolicy(max_retries=1))
        wf = eng.create_workflow("acme.com", "web")
        eng.start_workflow(wf)
        seq = ["completed", "failed", "completed", "skipped", "completed"]
        for i in range(10):
            r = eng.advance_workflow(wf, seq[i % len(seq)], "f")
            if r.get("workflow_status") in ("COMPLETED", "FAILED"):
                break
        return wf, _strip(eng.workflow_status(wf)["tasks"])

    wf_a, tasks_a = run("a")
    wf_b, tasks_b = run("b")
    assert wf_a == wf_b
    assert tasks_a == tasks_b


# ── runtime intelligence ──────────────────────────────────────────────────────
def test_runtime_intelligence(tmp_path):
    store = WorkflowStore(tmp_path / "w.db")
    eng = RuntimeEngine(store=store, now=1000.0, retry_policy=RetryPolicy(max_retries=1))
    wf = eng.create_workflow("acme.com", "web")
    eng.start_workflow(wf)
    eng.advance_workflow(wf, "completed")
    eng.advance_workflow(wf, "failed", "timeout")
    rep = RuntimeIntelligence(store=store).report()
    assert rep["total_workflows"] == 1
    assert rep["workflow_summary"].get("RUNNING") == 1
    assert "retry_statistics" in rep and rep["retry_statistics"]["tasks_total"] > 0
    assert rep["capability_runtime_coverage"]["exercised"] >= 1


def test_unknown_workflow_raises(tmp_path):
    with pytest.raises(WorkflowStateError):
        _engine(tmp_path).workflow_status("wf-nonexistent")
