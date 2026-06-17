"""
Findings Lifecycle Management (architecture spec Part 4).

A production findings store with an explicit state machine
(draft → validated → confirmed → rejected → reported → remediated), CVSS/CWE/OWASP
metadata, sha256-integrity evidence, and DB-layer dedup/correlation. The
draft→confirmed promotion is **evidence-gated**: no confirm without request +
response evidence (the two-signal / no-hallucinated-findings rule).

SQLite-backed (stdlib), redaction-on-store (operator secrets), deterministic.
"""

from .store import (
    ALLOWED_TRANSITIONS,
    EvidenceGateError,
    FindingsStore,
    FindingState,
    TransitionError,
    severity_for_cvss,
)

__all__ = [
    "FindingsStore",
    "FindingState",
    "ALLOWED_TRANSITIONS",
    "TransitionError",
    "EvidenceGateError",
    "severity_for_cvss",
]
