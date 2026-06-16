"""
Privilege-escalation / RBAC testing (attack section improvement #5 — uses the gated executor).

Extends the dual-session model from IDOR (horizontal) to VERTICAL privilege escalation: it requests
known-privileged endpoints as a LOW-privilege identity and flags any that return success — i.e. an
authorization control that fails to enforce role. Optionally diffs against an admin identity to
distinguish "truly privileged but unguarded" from "public anyway". Reuses `SessionContext` and the
injected (gated) executor; no direct network here. Conservative: a low-priv 200 on a privileged path
is a CANDIDATE the operator confirms.
"""

from __future__ import annotations

from typing import Dict, List, Optional
from urllib.parse import urljoin

# Common privileged paths to force-browse (operator can extend).
DEFAULT_PRIV_PATHS = ["/admin", "/admin/", "/admin/users", "/api/admin", "/api/v1/admin",
                      "/manage", "/settings/admin", "/dashboard/admin", "/internal", "/actuator",
                      "/api/users", "/api/v1/users", "/console"]


class PrivilegeEscalationTester:
    def __init__(self, executor):
        self.executor = executor          # gated HttpExecutor (or DryRunExecutor)

    def test(self, base_url: str, low_priv_session, paths: Optional[List[str]] = None,
             admin_session=None) -> Dict:
        paths = paths or DEFAULT_PRIV_PATHS
        rows: List[Dict] = []
        for path in paths:
            url = urljoin(base_url if base_url.endswith("/") else base_url + "/", path.lstrip("/"))
            low = self.executor(low_priv_session.apply({"method": "GET", "url": url, "headers": {}}))
            if not low.get("executed"):
                continue
            low_ok = (low.get("status") or 0) // 100 == 2
            row = {"path": path, "low_priv_status": low.get("status"),
                   "accessible_as_low_priv": low_ok}
            if admin_session is not None:
                adm = self.executor(admin_session.apply({"method": "GET", "url": url, "headers": {}}))
                adm_ok = (adm.get("status") or 0) // 100 == 2
                row["admin_status"] = adm.get("status")
                # privileged-but-unguarded: admin can reach it AND low-priv reaches it equivalently
                row["escalation"] = bool(low_ok and adm_ok and abs((low.get("length") or 0)
                                         - (adm.get("length") or 0)) <= max(32, 0.1 * (adm.get("length") or 1)))
            else:
                row["escalation"] = low_ok      # candidate: low-priv reached a privileged-looking path
            rows.append(row)
        escalations = [r for r in rows if r.get("escalation")]
        return {"base_url": base_url, "tested_paths": len(rows), "results": rows,
                "escalations": escalations, "confirmed": bool(escalations),
                "verdict": "candidate" if escalations else "suspected",
                "note": "low-priv access to privileged paths — confirm the path is truly restricted",
                "poc_only": True, "advisory": True}
