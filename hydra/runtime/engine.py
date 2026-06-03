"""
RuntimeEngine + RuntimeIntelligence (Phase I).

Coordinates workflow state over the Agent → Capability → Tool plan. It manages STATE
ONLY — it executes no tools, confirms no findings, and writes nothing to the canonical
wiki. Workflow/task ids are deterministic and stable (derived from the agent+capability
plan, NOT the learning-selected tool, so they don't drift as learning evolves).

Advisory by default; all state lives in the derived `data/workflows.db`.
"""

from __future__ import annotations

import hashlib
import time
from typing import Dict, List, Optional

from hydra.agents.planner import AgentPlanner
from hydra.capabilities.source_learning import SourceLearningStore
from hydra.capabilities.tool_selection import ToolSelector
from hydra.knowledge.verification import VerificationLearningStore
from hydra.runtime.workflows import (
    RetryPolicy,
    TaskState,
    WorkflowState,
    WorkflowStateError,
    WorkflowStore,
    validate_task_transition,
    validate_workflow_transition,
)

_ACTIONABLE = {TaskState.PENDING, TaskState.RETRYING}
_TASK_TERMINAL_OK = {TaskState.COMPLETED, TaskState.SKIPPED}


def _sha(s: str) -> str:
    return hashlib.sha1(s.encode()).hexdigest()[:12]


class RuntimeEngine:
    def __init__(self, store: Optional[WorkflowStore] = None,
                 planner: Optional[AgentPlanner] = None,
                 selector: Optional[ToolSelector] = None,
                 retry_policy: Optional[RetryPolicy] = None,
                 learning: Optional[SourceLearningStore] = None,
                 verification: Optional[VerificationLearningStore] = None,
                 now: Optional[float] = None):
        self.store = store or WorkflowStore()
        self.planner = planner or AgentPlanner()
        self.selector = selector or ToolSelector(
            self.planner.catalog, learning, verification, now=now)
        self.retry = retry_policy or RetryPolicy()

    # ── lifecycle ─────────────────────────────────────────────────────────────
    def create_workflow(self, target: str, target_type: str = "web",
                        prior_findings: int = 0) -> str:
        """Build the agent plan, resolve advisory tools, and persist a PENDING workflow.

        Deterministic & idempotent: the workflow_id is a stable hash of the
        agent:capability plan (NOT the learning-selected tool). Re-creating the same
        plan returns the same id without duplicating state."""
        plan = self.planner.plan(target, target_type, prior_findings)
        # Plan signature is tool-independent → stable ids across learning changes.
        sig_parts: List[str] = []
        task_specs: List[Dict] = []
        order = 0
        for step in plan.steps:
            caps = step.assigned_capabilities or [None]  # knowledge agents → one None-cap task
            for cap in caps:
                sig_parts.append(f"{step.agent_id}:{cap}")
                tool = self.selector.select(cap).tool if cap else None
                task_specs.append({"order_idx": order, "agent_id": step.agent_id,
                                   "capability_id": cap, "tool_id": tool})
                order += 1
        workflow_id = "wf-" + _sha(f"{target}|{target_type}|" + "|".join(sig_parts))
        for t in task_specs:
            t["task_id"] = "task-" + _sha(
                f"{workflow_id}|{t['order_idx']}|{t['agent_id']}|{t['capability_id']}")
        self.store.create_workflow(workflow_id, target, target_type, task_specs)
        return workflow_id

    def start_workflow(self, workflow_id: str) -> Dict:
        wf = self._require(workflow_id)
        src = WorkflowState(wf["status"])
        validate_workflow_transition(src, WorkflowState.RUNNING)
        self.store.set_workflow_status(workflow_id, WorkflowState.RUNNING)
        return self.workflow_status(workflow_id)

    def advance_workflow(self, workflow_id: str, outcome: str = "completed",
                         failure_reason: str = "") -> Dict:
        """Process the next actionable task with a caller-supplied outcome
        (completed|failed|skipped). State only — nothing is executed. Enforces the
        deterministic retry policy on failure."""
        wf = self._require(workflow_id)
        if WorkflowState(wf["status"]) is not WorkflowState.RUNNING:
            raise WorkflowStateError(f"workflow {workflow_id} is {wf['status']}, not RUNNING")

        task = self._next_actionable(workflow_id)
        if task is None:
            return self._finalize(workflow_id)

        now = time.time()
        state = TaskState(task["status"])
        # Move the task into RUNNING (PENDING→RUNNING or RETRYING→RUNNING).
        if state is TaskState.RETRYING:
            validate_task_transition(state, TaskState.RUNNING)
        else:
            validate_task_transition(state, TaskState.RUNNING)
        self.store.update_task(task["task_id"], status=TaskState.RUNNING.value, started_at=now)

        result = {"task_id": task["task_id"], "workflow_id": workflow_id}
        if outcome == "completed":
            validate_task_transition(TaskState.RUNNING, TaskState.COMPLETED)
            self.store.update_task(task["task_id"], status=TaskState.COMPLETED.value, completed_at=time.time())
            result["task_status"] = TaskState.COMPLETED.value
        elif outcome == "skipped":
            validate_task_transition(TaskState.RUNNING, TaskState.SKIPPED)
            self.store.update_task(task["task_id"], status=TaskState.SKIPPED.value, completed_at=time.time())
            result["task_status"] = TaskState.SKIPPED.value
        elif outcome == "failed":
            attempts = int(task["attempts"]) + 1
            validate_task_transition(TaskState.RUNNING, TaskState.FAILED)
            if attempts <= self.retry.max_retries:
                # retryable: FAILED → RETRYING (deterministic backoff recorded)
                self.store.update_task(task["task_id"], status=TaskState.FAILED.value,
                                       attempts=attempts, failure_reason=failure_reason)
                validate_task_transition(TaskState.FAILED, TaskState.RETRYING)
                self.store.update_task(task["task_id"], status=TaskState.RETRYING.value)
                result["task_status"] = TaskState.RETRYING.value
                result["attempts"] = attempts
                result["backoff_seconds"] = self.retry.backoff_for(attempts)
            else:
                # exhausted retries → FAILED (terminal)
                self.store.update_task(task["task_id"], status=TaskState.FAILED.value,
                                       attempts=attempts, failure_reason=failure_reason,
                                       completed_at=time.time())
                result["task_status"] = TaskState.FAILED.value
                result["attempts"] = attempts
        else:
            raise ValueError(f"outcome must be completed|failed|skipped, got {outcome!r}")

        finalize = self._finalize(workflow_id)
        result["workflow_status"] = finalize["status"]
        return result

    def cancel_workflow(self, workflow_id: str) -> Dict:
        wf = self._require(workflow_id)
        validate_workflow_transition(WorkflowState(wf["status"]), WorkflowState.CANCELLED)
        self.store.set_workflow_status(workflow_id, WorkflowState.CANCELLED)
        return self.workflow_status(workflow_id)

    def workflow_status(self, workflow_id: str) -> Dict:
        wf = self._require(workflow_id)
        return {"workflow": wf, "tasks": self.store.get_tasks(workflow_id)}

    # ── helpers ────────────────────────────────────────────────────────────────
    def _require(self, workflow_id: str) -> Dict:
        wf = self.store.get_workflow(workflow_id)
        if wf is None:
            raise WorkflowStateError(f"unknown workflow: {workflow_id}")
        return wf

    def _next_actionable(self, workflow_id: str) -> Optional[Dict]:
        for t in self.store.get_tasks(workflow_id):   # ordered by order_idx, task_id
            if TaskState(t["status"]) in _ACTIONABLE:
                return t
        return None

    def _finalize(self, workflow_id: str) -> Dict:
        """If no actionable tasks remain, settle the workflow deterministically."""
        wf = self._require(workflow_id)
        if WorkflowState(wf["status"]) is not WorkflowState.RUNNING:
            return wf
        tasks = self.store.get_tasks(workflow_id)
        if any(TaskState(t["status"]) in _ACTIONABLE for t in tasks):
            return wf
        any_failed = any(TaskState(t["status"]) is TaskState.FAILED for t in tasks)
        final = WorkflowState.FAILED if any_failed else WorkflowState.COMPLETED
        self.store.set_workflow_status(workflow_id, final)
        return self._require(workflow_id)


class RuntimeIntelligence:
    """Read-only runtime analytics. Does not affect planning or learning."""

    def __init__(self, store: Optional[WorkflowStore] = None,
                 planner: Optional[AgentPlanner] = None):
        self.store = store or WorkflowStore()
        self.planner = planner or AgentPlanner()

    def report(self) -> Dict:
        workflows = self.store.list_workflows()
        tasks = self.store.all_tasks()

        wf_summary: Dict[str, int] = {}
        for w in workflows:
            wf_summary[w["status"]] = wf_summary.get(w["status"], 0) + 1

        agent_stats: Dict[str, Dict[str, int]] = {}
        failures: Dict[str, int] = {}
        cap_seen = set()
        attempts_hist: Dict[int, int] = {}
        retried = 0
        for t in tasks:
            a = agent_stats.setdefault(t["agent_id"] or "—", {})
            a[t["status"]] = a.get(t["status"], 0) + 1
            if t["capability_id"]:
                cap_seen.add(t["capability_id"])
            if t["status"] == TaskState.FAILED.value and t["failure_reason"]:
                failures[t["failure_reason"]] = failures.get(t["failure_reason"], 0) + 1
            n = int(t["attempts"] or 0)
            attempts_hist[n] = attempts_hist.get(n, 0) + 1
            if n > 1:
                retried += 1

        total_caps = self.planner.catalog.count()
        return {
            "workflow_summary": wf_summary,
            "total_workflows": len(workflows),
            "agent_runtime_stats": {k: dict(sorted(v.items())) for k, v in sorted(agent_stats.items())},
            "failure_patterns": dict(sorted(failures.items(), key=lambda kv: (-kv[1], kv[0]))),
            "retry_statistics": {
                "tasks_total": len(tasks), "tasks_retried": retried,
                "attempts_histogram": dict(sorted(attempts_hist.items())),
                "retry_rate": round(retried / len(tasks), 4) if tasks else 0.0,
            },
            "capability_runtime_coverage": {
                "exercised": len(cap_seen), "catalog_total": total_caps,
                "coverage_pct": round(100 * len(cap_seen) / total_caps, 1) if total_caps else 0.0,
            },
        }
