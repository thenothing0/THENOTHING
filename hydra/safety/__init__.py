"""
Trust-boundary safety layer — the fixes for AUDIT.md TN-1 / TN-2 / TN-7.

Three primitives the LLM-driven loop and the knowledge-fusion/learning paths use
to keep adversarial target data from steering the agent or leaking operator
secrets:

  * ``redact(text)``           — mask operator secrets BEFORE they cross a trust
                                 boundary (persisted memory, snapshots, learning,
                                 and outbound prompts to *hosted* LLMs). TN-7.
                                 Patterns cover the gaps PentesterFlow's audit
                                 called out (URL userinfo H9, 2-segment JWT H10).
  * ``fence_untrusted(text, source)`` — wrap target-derived data in explicit
                                 "data, not instructions" delimiters so indirect
                                 prompt injection in tool output / captured
                                 traffic is contained. TN-2.
  * ``scan_injection(text)``   — heuristic detector for prompt-injection / agent-
                                 steering payloads; used to flag (and quarantine)
                                 learned "lessons" before they enter the cross-
                                 session knowledge base. TN-1.

Deterministic, dependency-free, linear-time (no catastrophic backtracking).
"""

from .trust_boundary import (
    InjectionHit,
    fence_untrusted,
    redact,
    scan_injection,
)

__all__ = ["redact", "fence_untrusted", "scan_injection", "InjectionHit"]
