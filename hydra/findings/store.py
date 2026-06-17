"""Findings lifecycle store — SQLite, state machine, evidence-gated promotion."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional


class FindingState:
    DRAFT = "draft"
    VALIDATED = "validated"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    REPORTED = "reported"
    REMEDIATED = "remediated"


# Directed state machine. A finding can be rejected from any pre-report state;
# confirm requires passing the evidence gate (enforced in transition()).
ALLOWED_TRANSITIONS: Dict[str, set] = {
    FindingState.DRAFT: {FindingState.VALIDATED, FindingState.REJECTED},
    FindingState.VALIDATED: {FindingState.CONFIRMED, FindingState.REJECTED},
    FindingState.CONFIRMED: {FindingState.REPORTED, FindingState.REJECTED},
    FindingState.REPORTED: {FindingState.REMEDIATED},
    FindingState.REMEDIATED: set(),
    FindingState.REJECTED: set(),
}

_SEVERITIES = ("info", "low", "medium", "high", "critical")


class TransitionError(RuntimeError):
    """Raised on an illegal state transition."""


class EvidenceGateError(RuntimeError):
    """Raised when promoting to `confirmed` without required evidence."""


def severity_for_cvss(score: float) -> str:
    """CVSS v3.1 qualitative band for a base score."""
    if score <= 0:
        return "info"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def _normalize_endpoint(endpoint: str) -> str:
    """Collapse numeric/uuid path segments so /orders/1043 and /orders/9 dedup together."""
    e = (endpoint or "").split("?", 1)[0].rstrip("/")
    e = re.sub(r"/\d+", "/{id}", e)
    e = re.sub(r"/[0-9a-fA-F-]{16,}", "/{id}", e)
    return e or "/"


class FindingsStore:
    """SQLite findings store. One DB per engagement workspace (or shared)."""

    def __init__(self, db_path: str = "findings/findings.db"):
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
                CREATE TABLE IF NOT EXISTS findings (
                  id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL, title TEXT NOT NULL,
                  state TEXT NOT NULL DEFAULT 'draft', severity TEXT NOT NULL DEFAULT 'info',
                  vuln_class TEXT, cvss_vector TEXT, cvss_score REAL,
                  cwe TEXT, owasp TEXT,
                  asset TEXT, endpoint TEXT, method TEXT, parameter TEXT, payload TEXT,
                  impact TEXT, remediation TEXT, dedup_key TEXT NOT NULL,
                  created_at TEXT NOT NULL, updated_at TEXT,
                  UNIQUE(engagement_id, dedup_key)
                );
                CREATE TABLE IF NOT EXISTS evidence (
                  id TEXT PRIMARY KEY, finding_id TEXT NOT NULL,
                  kind TEXT NOT NULL, content TEXT, sha256 TEXT NOT NULL, created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_findings_state ON findings(engagement_id, state);
                CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence(finding_id);
                """
            )

    # ── create / read ───────────────────────────────────────────────────────────
    def create(self, engagement_id: str, title: str, vuln_class: str = "",
               severity: str = "info", asset: str = "", endpoint: str = "",
               method: str = "GET", parameter: str = "", payload: str = "",
               impact: str = "", remediation: str = "", cwe: str = "",
               owasp: str = "") -> str:
        sev = severity if severity in _SEVERITIES else "info"
        dedup = hashlib.sha256(
            f"{(vuln_class or title).lower()}|{_normalize_endpoint(endpoint)}".encode()
        ).hexdigest()[:24]
        fid = f"F-{uuid.uuid4().hex[:12]}"
        now = _now()
        with self._conn() as c:
            existing = c.execute(
                "SELECT id FROM findings WHERE engagement_id=? AND dedup_key=?",
                (engagement_id, dedup)).fetchone()
            if existing:
                return existing["id"]  # idempotent: same root cause = same finding
            c.execute(
                """INSERT INTO findings (id, engagement_id, title, state, severity, vuln_class,
                   cwe, owasp, asset, endpoint, method, parameter, payload, impact, remediation,
                   dedup_key, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (fid, engagement_id, title, FindingState.DRAFT, sev, vuln_class, cwe, owasp,
                 asset, endpoint, method, parameter, payload, impact, remediation, dedup, now))
        return fid

    def get(self, finding_id: str) -> Optional[Dict]:
        with self._conn() as c:
            row = c.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
            if not row:
                return None
            d = dict(row)
            d["evidence"] = [dict(e) for e in c.execute(
                "SELECT id, kind, sha256, created_at FROM evidence WHERE finding_id=?",
                (finding_id,)).fetchall()]
            return d

    def list(self, engagement_id: str, state: str = "") -> List[Dict]:
        q = "SELECT * FROM findings WHERE engagement_id=?"
        args = [engagement_id]
        if state:
            q += " AND state=?"
            args.append(state)
        with self._conn() as c:
            return [dict(r) for r in c.execute(q + " ORDER BY created_at", args).fetchall()]

    # ── evidence ─────────────────────────────────────────────────────────────────
    def add_evidence(self, finding_id: str, kind: str, content: str) -> Dict:
        from hydra.safety import redact
        safe = redact(content or "")
        sha = hashlib.sha256((content or "").encode()).hexdigest()
        eid = f"E-{uuid.uuid4().hex[:12]}"
        with self._conn() as c:
            if not c.execute("SELECT 1 FROM findings WHERE id=?", (finding_id,)).fetchone():
                raise KeyError(f"unknown finding {finding_id}")
            c.execute("INSERT INTO evidence (id, finding_id, kind, content, sha256, created_at) "
                      "VALUES (?,?,?,?,?,?)", (eid, finding_id, kind, safe, sha, _now()))
        return {"evidence_id": eid, "sha256": sha, "kind": kind}

    def _evidence_kinds(self, c, finding_id: str) -> set:
        return {r["kind"] for r in c.execute(
            "SELECT DISTINCT kind FROM evidence WHERE finding_id=?", (finding_id,)).fetchall()}

    # ── lifecycle ────────────────────────────────────────────────────────────────
    def transition(self, finding_id: str, to_state: str) -> Dict:
        with self._conn() as c:
            row = c.execute("SELECT state FROM findings WHERE id=?", (finding_id,)).fetchone()
            if not row:
                raise KeyError(f"unknown finding {finding_id}")
            frm = row["state"]
            if to_state not in ALLOWED_TRANSITIONS.get(frm, set()):
                raise TransitionError(f"illegal transition {frm} -> {to_state}")
            # Evidence gate: no confirm without request + response (anti-hallucination).
            if to_state == FindingState.CONFIRMED:
                kinds = self._evidence_kinds(c, finding_id)
                if not ({"request", "response"} <= kinds):
                    raise EvidenceGateError(
                        "confirm requires both 'request' and 'response' evidence "
                        f"(have: {sorted(kinds) or 'none'})")
            c.execute("UPDATE findings SET state=?, updated_at=? WHERE id=?",
                      (to_state, _now(), finding_id))
        return {"id": finding_id, "from": frm, "to": to_state}

    def score(self, finding_id: str, cvss_vector: str = "", cvss_score: float = 0.0) -> Dict:
        sev = severity_for_cvss(float(cvss_score or 0.0))
        with self._conn() as c:
            c.execute("UPDATE findings SET cvss_vector=?, cvss_score=?, severity=?, updated_at=? "
                      "WHERE id=?", (cvss_vector, float(cvss_score or 0.0), sev, _now(), finding_id))
        return {"id": finding_id, "cvss_score": cvss_score, "severity": sev}

    def correlate(self, engagement_id: str) -> Dict:
        """Report dedup clusters by dedup_key (creation is already idempotent)."""
        with self._conn() as c:
            rows = c.execute(
                "SELECT dedup_key, COUNT(*) n, GROUP_CONCAT(id) ids FROM findings "
                "WHERE engagement_id=? GROUP BY dedup_key HAVING n>1", (engagement_id,)).fetchall()
        return {"clusters": [{"dedup_key": r["dedup_key"], "ids": r["ids"].split(",")}
                             for r in rows]}

    def summary(self, engagement_id: str) -> Dict:
        with self._conn() as c:
            by_state = {r["state"]: r["n"] for r in c.execute(
                "SELECT state, COUNT(*) n FROM findings WHERE engagement_id=? GROUP BY state",
                (engagement_id,)).fetchall()}
            by_sev = {r["severity"]: r["n"] for r in c.execute(
                "SELECT severity, COUNT(*) n FROM findings WHERE engagement_id=? GROUP BY severity",
                (engagement_id,)).fetchall()}
        return {"by_state": by_state, "by_severity": by_sev,
                "total": sum(by_state.values())}


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time()))
