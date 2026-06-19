"""Engagement store + RBAC."""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional


class Role:
    ADMIN = "admin"
    LEAD = "lead"
    OPERATOR = "operator"
    VIEWER = "viewer"


ROLES = (Role.ADMIN, Role.LEAD, Role.OPERATOR, Role.VIEWER)

# Action → minimum role rank required. Higher rank ⊇ lower rank's permissions.
_RANK = {Role.VIEWER: 0, Role.OPERATOR: 1, Role.LEAD: 2, Role.ADMIN: 3}

# action -> minimum role
PERMISSIONS: Dict[str, str] = {
    "read": Role.VIEWER,
    "run_recon": Role.OPERATOR,
    "run_scan": Role.OPERATOR,
    "create_finding": Role.OPERATOR,
    "validate_finding": Role.OPERATOR,
    "record_coverage": Role.OPERATOR,
    "run_exploit": Role.LEAD,
    "confirm_finding": Role.LEAD,
    "report_finding": Role.LEAD,
    "export_report": Role.LEAD,
    "manage_team": Role.ADMIN,
    "manage_engagement": Role.ADMIN,
    "manage_scope": Role.ADMIN,
}


def can(role: str, action: str) -> bool:
    """True if `role` is permitted to perform `action`."""
    need = PERMISSIONS.get(action)
    if need is None:
        return False
    return _RANK.get(role, -1) >= _RANK[need]


class EngagementStore:
    def __init__(self, db_path: str = ".thenothing/engagements/engagements.db"):
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self._path)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        return c

    def _init(self) -> None:
        with self._conn() as c:
            c.executescript(
                """
                CREATE TABLE IF NOT EXISTS engagements (
                  id TEXT PRIMARY KEY, client TEXT NOT NULL, name TEXT NOT NULL,
                  scope TEXT NOT NULL, sow_start TEXT, sow_end TEXT,
                  status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS members (
                  engagement_id TEXT NOT NULL, username TEXT NOT NULL,
                  role TEXT NOT NULL, added_at TEXT NOT NULL,
                  PRIMARY KEY (engagement_id, username)
                );
                """
            )

    def create(self, client: str, name: str, scope: Optional[List[str]] = None,
               sow_start: str = "", sow_end: str = "", owner: str = "") -> str:
        eid = f"ENG-{uuid.uuid4().hex[:10]}"
        now = _now()
        with self._conn() as c:
            c.execute("INSERT INTO engagements (id, client, name, scope, sow_start, sow_end, "
                      "status, created_at) VALUES (?,?,?,?,?,?,?,?)",
                      (eid, client, name, json.dumps(scope or []), sow_start, sow_end,
                       "active", now))
            if owner:
                c.execute("INSERT INTO members (engagement_id, username, role, added_at) "
                          "VALUES (?,?,?,?)", (eid, owner, Role.ADMIN, now))
        return eid

    def get(self, engagement_id: str) -> Optional[Dict]:
        with self._conn() as c:
            row = c.execute("SELECT * FROM engagements WHERE id=?", (engagement_id,)).fetchone()
            if not row:
                return None
            d = dict(row)
            d["scope"] = json.loads(d.get("scope") or "[]")
            d["team"] = [dict(m) for m in c.execute(
                "SELECT username, role FROM members WHERE engagement_id=?",
                (engagement_id,)).fetchall()]
            return d

    def list(self) -> List[Dict]:
        with self._conn() as c:
            return [{"id": r["id"], "client": r["client"], "name": r["name"],
                     "status": r["status"]} for r in c.execute(
                        "SELECT * FROM engagements ORDER BY created_at").fetchall()]

    def add_member(self, engagement_id: str, username: str, role: str) -> Dict:
        if role not in ROLES:
            raise ValueError(f"unknown role '{role}' ({', '.join(ROLES)})")
        with self._conn() as c:
            if not c.execute("SELECT 1 FROM engagements WHERE id=?",
                             (engagement_id,)).fetchone():
                raise KeyError(f"unknown engagement {engagement_id}")
            c.execute("INSERT OR REPLACE INTO members (engagement_id, username, role, added_at) "
                      "VALUES (?,?,?,?)", (engagement_id, username, role, _now()))
        return {"engagement_id": engagement_id, "username": username, "role": role}

    def role_of(self, engagement_id: str, username: str) -> Optional[str]:
        with self._conn() as c:
            row = c.execute("SELECT role FROM members WHERE engagement_id=? AND username=?",
                            (engagement_id, username)).fetchone()
            return row["role"] if row else None

    def authorize(self, engagement_id: str, username: str, action: str) -> Dict:
        """RBAC check: may `username` perform `action` on this engagement?"""
        role = self.role_of(engagement_id, username)
        if role is None:
            return {"allowed": False, "reason": f"'{username}' is not a member"}
        return {"allowed": can(role, action), "role": role,
                "reason": f"role '{role}' {'may' if can(role, action) else 'may NOT'} {action}"}

    def set_status(self, engagement_id: str, status: str) -> Dict:
        with self._conn() as c:
            c.execute("UPDATE engagements SET status=? WHERE id=?", (status, engagement_id))
        return {"id": engagement_id, "status": status}


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time()))
