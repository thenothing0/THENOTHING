"""
Login-flow automation (attack section — runtime/I/O side).

Builds an authenticated `SessionContext` by submitting OPERATOR-SUPPLIED credentials to an in-scope
login endpoint and capturing the resulting session (Set-Cookie + any bearer/token in the JSON body).
This is authenticated-testing SETUP for an authorized target — the operator's own test accounts — not
credential theft. GATED: the login endpoint must be bug-bounty in-scope (deny-by-default), and the
single request is rate-/size-bounded. Network I/O lives here, never in `hydra/attack/`.
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from http.cookies import SimpleCookie
from typing import Dict, Optional
from urllib.parse import urlencode

from hydra.attack_runtime.session import SessionContext


class LoginError(RuntimeError):
    pass


class LoginFlow:
    def __init__(self, gate=None, timeout: float = 15.0, verify_tls: bool = False):
        if gate is None:
            from hydra.authorization import BugBountyAuthorizationGate
            gate = BugBountyAuthorizationGate()
        self.gate = gate
        self.timeout = timeout
        self._ctx = None if verify_tls else ssl._create_unverified_context()

    def login(self, login_url: str, fields: Dict[str, str], json_body: bool = False,
              name: str = "auth", token_keys=("token", "access_token", "jwt", "id_token")
              ) -> Optional[SessionContext]:
        """Authenticate and return a SessionContext, or None if the gate denies the login endpoint."""
        decision = self.gate.authorize(login_url, "active_recon")     # login is an active action
        if not decision.authorized:
            return None
        headers = {"User-Agent": "hydra-poc/1.0 (authorized bug-bounty testing)"}
        if json_body:
            data = json.dumps(fields).encode()
            headers["Content-Type"] = "application/json"
        else:
            data = urlencode(fields).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        req = urllib.request.Request(login_url, data=data, method="POST", headers=headers)
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=self._ctx))
        try:
            with opener.open(req, timeout=self.timeout) as r:
                set_cookies = r.headers.get_all("Set-Cookie") or []
                body = r.read(1 << 20)
        except urllib.error.HTTPError as e:
            set_cookies = (e.headers.get_all("Set-Cookie") or []) if e.headers else []
            try:
                body = e.read(1 << 20)
            except Exception:
                body = b""
        except Exception as e:
            raise LoginError(f"login request failed: {e}") from e

        cookies: Dict[str, str] = {}
        for raw in set_cookies:
            c = SimpleCookie()
            c.load(raw)
            for k, morsel in c.items():
                cookies[k] = morsel.value
        bearer = ""
        try:
            j = json.loads(body.decode("utf-8", "replace"))
            if isinstance(j, dict):
                for k in token_keys:
                    if j.get(k):
                        bearer = str(j[k])
                        break
        except ValueError:
            pass
        return SessionContext(name=name, bearer=bearer, cookies=cookies)
