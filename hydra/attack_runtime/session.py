"""
Authenticated session context (attack section improvement #2 — runtime/I/O side).

Most high-bounty bugs (IDOR, broken access control, ATO) live behind authentication. A
`SessionContext` carries an identity's auth material (bearer token, cookies, extra headers) and
applies it to an outgoing request. `SessionManager` holds named identities so the workflow can test
the SAME resource as two users (the access-control diff). Operator-supplied credentials only — this is
authenticated testing of an authorized target, never credential theft.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass
class SessionContext:
    name: str = "anon"
    bearer: str = ""
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)

    def apply(self, request: Dict) -> Dict:
        """Return a copy of `request` with this identity's auth material merged in."""
        r = dict(request)
        h = dict(r.get("headers") or {})
        if self.bearer:
            h.setdefault("Authorization", f"Bearer {self.bearer}")
        for k, v in self.headers.items():
            h[k] = v
        if self.cookies:
            existing = dict(c.split("=", 1) for c in h.get("Cookie", "").split("; ") if "=" in c)
            existing.update(self.cookies)
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in existing.items())
        r["headers"] = h
        r["identity"] = self.name
        return r

    @property
    def authenticated(self) -> bool:
        return bool(self.bearer or self.cookies or self.headers)


class SessionManager:
    def __init__(self):
        self._sessions: Dict[str, SessionContext] = {}

    def add(self, name: str, bearer: str = "", cookies: Optional[Dict[str, str]] = None,
            headers: Optional[Dict[str, str]] = None) -> SessionContext:
        s = SessionContext(name=name, bearer=bearer, cookies=cookies or {}, headers=headers or {})
        self._sessions[name] = s
        return s

    def get(self, name: str) -> Optional[SessionContext]:
        return self._sessions.get(name)

    def identities(self):
        return sorted(self._sessions)
