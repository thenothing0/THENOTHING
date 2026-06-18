"""
Session Resume & Compaction (architecture spec Part 3 / PentesterFlow parity).

Durable engagement sessions: save conversation/work state to disk, resume it
later with a recap, periodically snapshot a redacted context, and compact long
histories into a structured persistent memory so an engagement survives restarts
without blowing the context window.

  * SessionStore   — crash-safe (tmp + atomic rename) JSON session persistence.
  * SessionMemory  — the structured 11-section checkpoint compaction produces.
  * compact_history / merge_memory — fold a transcript into persistent memory.

All persisted text is secret-redacted (operator-secret leakage boundary).
Deterministic; stdlib only.
"""

from .store import (
    SessionMemory,
    SessionStore,
    compact_messages,
    format_recap,
    merge_memory,
)

__all__ = [
    "SessionStore",
    "SessionMemory",
    "merge_memory",
    "compact_messages",
    "format_recap",
]
