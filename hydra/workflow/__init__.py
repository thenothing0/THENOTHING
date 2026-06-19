"""
Pentest Workflow Engine (architecture spec Part 9).

An explicit lifecycle state machine:

  scope → recon → enumeration → validation → exploitation → evidence
        → coverage_review → reporting → done            (halt/resume from any state)

Each transition has a precondition + an approval policy + a durable checkpoint, so
a long engagement survives restarts (resume from the last checkpoint) and an
emergency stop freezes it cleanly. SQLite-backed (WAL); deterministic.

Distinct from the generic `hydra/runtime` agent-task store — this models the
human pentest lifecycle, not tool-task orchestration.
"""

from .engine import (
    STATES,
    TRANSITIONS,
    PentestWorkflow,
    WorkflowError,
)

__all__ = ["PentestWorkflow", "STATES", "TRANSITIONS", "WorkflowError"]
