"""Coverage matrix store + scoring + the /next engine."""

from __future__ import annotations

import sqlite3
import time
import uuid
from pathlib import Path
from typing import Dict, List

# Vuln classes that most elevate severity when found in an auth area — used to
# weight the /next engine and the risk score toward high-value untested work.
HIGH_VALUE_CLASSES = {
    "idor": 3.0, "bola": 3.0, "broken_access_control": 3.0, "auth_bypass": 3.0,
    "sqli": 2.5, "rce": 3.0, "ssrf": 2.5, "ssti": 2.5, "deserialization": 2.5,
    "graphql_authz": 2.0, "jwt": 2.0, "race": 1.5, "xss": 1.0, "open_redirect": 0.5,
}
_DEFAULT_WEIGHT = 1.0
_STATUSES = ("untested", "passed", "failed", "skipped", "waf-blocked")
_SEV_WEIGHT = {"info": 0.0, "low": 1.0, "medium": 3.0, "high": 7.0, "critical": 10.0}


class CoverageStore:
    def __init__(self, db_path: str = "findings/coverage.db"):
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
                CREATE TABLE IF NOT EXISTS coverage (
                  id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL,
                  asset TEXT, endpoint TEXT, method TEXT DEFAULT 'GET',
                  parameter TEXT DEFAULT '', auth_area TEXT DEFAULT '',
                  vuln_class TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'untested',
                  evidence_finding_id TEXT, tested_at TEXT, created_at TEXT NOT NULL,
                  UNIQUE(engagement_id, endpoint, method, parameter, vuln_class)
                );
                CREATE INDEX IF NOT EXISTS idx_cov_eng_status
                  ON coverage(engagement_id, status);
                """
            )

    def record(self, engagement_id: str, endpoint: str, vuln_class: str,
               method: str = "GET", parameter: str = "", asset: str = "",
               auth_area: str = "", status: str = "untested",
               evidence_finding_id: str = "") -> Dict:
        st = status if status in _STATUSES else "untested"
        now = _now()
        with self._conn() as c:
            row = c.execute(
                "SELECT id FROM coverage WHERE engagement_id=? AND endpoint=? AND method=? "
                "AND parameter=? AND vuln_class=?",
                (engagement_id, endpoint, method, parameter, vuln_class)).fetchone()
            if row:
                c.execute("UPDATE coverage SET status=?, asset=?, auth_area=?, "
                          "evidence_finding_id=?, tested_at=? WHERE id=?",
                          (st, asset, auth_area, evidence_finding_id,
                           now if st != "untested" else None, row["id"]))
                return {"id": row["id"], "updated": True, "status": st}
            cid = f"C-{uuid.uuid4().hex[:12]}"
            c.execute(
                "INSERT INTO coverage (id, engagement_id, asset, endpoint, method, parameter, "
                "auth_area, vuln_class, status, evidence_finding_id, tested_at, created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (cid, engagement_id, asset, endpoint, method, parameter, auth_area, vuln_class,
                 st, evidence_finding_id, now if st != "untested" else None, now))
        return {"id": cid, "updated": False, "status": st}

    def matrix(self, engagement_id: str) -> List[Dict]:
        with self._conn() as c:
            return [dict(r) for r in c.execute(
                "SELECT endpoint, method, parameter, auth_area, vuln_class, status "
                "FROM coverage WHERE engagement_id=? ORDER BY endpoint", (engagement_id,)).fetchall()]

    def summary(self, engagement_id: str, open_finding_severities: List[str] | None = None) -> Dict:
        rows = self.matrix(engagement_id)
        total = len(rows)
        tested = sum(1 for r in rows if r["status"] in ("passed", "failed", "waf-blocked"))
        coverage_score = round(tested / total, 3) if total else 0.0

        endpoints = {r["endpoint"] for r in rows if r["endpoint"]}
        params = {(r["endpoint"], r["parameter"]) for r in rows if r["parameter"]}
        auth_areas = {r["auth_area"] for r in rows if r["auth_area"]}
        # Bounded, monotonic normalization of breadth → 0..100.
        surface_raw = 2 * len(endpoints) + len(params) + 3 * len(auth_areas)
        attack_surface_score = round(min(100.0, surface_raw), 1)

        # Risk = open-finding severity weight + uncovered-high-value weight.
        sev_weight = sum(_SEV_WEIGHT.get(s, 0.0) for s in (open_finding_severities or []))
        uncovered_hv = sum(
            HIGH_VALUE_CLASSES.get(r["vuln_class"], _DEFAULT_WEIGHT)
            for r in rows if r["status"] == "untested")
        risk_score = round(sev_weight + uncovered_hv, 1)

        return {
            "total_tuples": total, "tested_tuples": tested,
            "coverage_score": coverage_score,
            "attack_surface_score": attack_surface_score,
            "risk_score": risk_score,
            "endpoints": len(endpoints), "parameters": len(params),
            "auth_areas": len(auth_areas),
            "by_status": _counts(rows, "status"),
        }

    def next(self, engagement_id: str, limit: int = 10) -> List[Dict]:
        """Highest-value untested tuples: prefer auth-area × high-impact vuln class."""
        rows = [r for r in self.matrix(engagement_id) if r["status"] == "untested"]

        def value(r: Dict) -> float:
            base = HIGH_VALUE_CLASSES.get(r["vuln_class"], _DEFAULT_WEIGHT)
            return base * (1.5 if r["auth_area"] else 1.0)

        rows.sort(key=value, reverse=True)
        return [{"endpoint": r["endpoint"], "method": r["method"], "parameter": r["parameter"],
                 "auth_area": r["auth_area"], "vuln_class": r["vuln_class"],
                 "value": round(value(r), 2)} for r in rows[:limit]]


def _counts(rows: List[Dict], key: str) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for r in rows:
        out[r[key]] = out.get(r[key], 0) + 1
    return out


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time()))
