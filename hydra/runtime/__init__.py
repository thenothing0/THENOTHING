"""
hydra.runtime — Execution Runtime & Workflow Engine (Phase I).

A deterministic execution runtime ABOVE the agent/capability/tool layers. It
coordinates workflow state, transitions, retries and execution history — but executes
NO tools and materializes NOTHING into the canonical wiki.

All runtime state is derived/disposable under `data/workflows.db`. Advisory by default:
the engine manages state, it does not act. Canonical knowledge behavior, promotion.py
and confidence.py are untouched.
"""

from hydra.runtime.workflows import (  # noqa: F401
    RetryPolicy,
    TASK_TRANSITIONS,
    TaskState,
    WORKFLOW_TRANSITIONS,
    WorkflowState,
    WorkflowStore,
    WorkflowStateError,
)
