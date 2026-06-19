"""
Engagement Management & RBAC (architecture spec Part 8 / enterprise).

An Engagement binds a client + SoW window + team + authorized scope to all the
findings/coverage/workflow rows of a job, and RBAC governs who may do what:

    admin    — manage engagements + team + everything below
    lead     — confirm/report findings, export, run exploit-tier actions
    operator — create/validate findings, run scans, record coverage
    viewer   — read-only

Deterministic, SQLite-backed, stdlib-only.
"""

from .store import (
    PERMISSIONS,
    ROLES,
    EngagementStore,
    Role,
    can,
)

__all__ = ["EngagementStore", "Role", "ROLES", "PERMISSIONS", "can"]
