"""
Verification Learning & Validation Intelligence (Phase F).

Learns HOW findings get validated — which verification methods succeed for which
vulnerability classes, which evidence is most predictive, which sequences work — and
turns that into advisory verification playbooks.

Built on the proven Phase-D/E pattern and its hardening lessons:
  * **Event-sourced + derived/disposable** under `data/` (gitignored); every statistic
    is a pure function of the raw event log → rebuildable & deterministic.
  * **Idempotent** recording via an optional `dedup_key` (UNIQUE) — retries/concurrent
    workers converge (F-D1 lesson).
  * **WAL** journal mode for multi-process safety (F-D5 lesson).
  * **Single-query aggregation** (F-D4 lesson).

Invariants (unchanged): wiki canonical (this writes only to `data/`); promotion.py and
confidence.py untouched; advisory only — NO autonomous confirmation or exploitation.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

_DEFAULT_DB = Path(__file__).resolve().parents[2] / "data" / "verification_learning.db"

OUTCOME_SUCCESS = "success"
OUTCOME_FAILURE = "failure"


@dataclass
class MethodStats:
    method: str
    attempts: int = 0
    successes: int = 0
    failures: int = 0
    evidence_strength: float = 0.0   # mean over events

    @property
    def success_rate(self) -> float:
        # Laplace-smoothed: stable with little data, deterministic.
        return round((self.successes + 1) / (self.attempts + 2), 4)

    @property
    def confidence(self) -> float:
        # Grows with sample size toward the observed rate (deterministic).
        raw = self.successes / self.attempts if self.attempts else 0.0
        weight = self.attempts / (self.attempts + 5)
        return round(raw * weight + 0.5 * (1 - weight), 4)

    def to_dict(self) -> Dict:
        return {"method": self.method, "attempts": self.attempts,
                "successes": self.successes, "failures": self.failures,
                "evidence_strength": round(self.evidence_strength, 4),
                "success_rate": self.success_rate, "confidence": self.confidence}


class VerificationLearningStore:
    def __init__(self, db_path: Optional[Path | str] = None):
        self.db_path = Path(db_path) if db_path else Path(
            os.environ.get("HYDRA_VERIFICATION_DB") or _DEFAULT_DB)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(str(self.db_path), timeout=30)
        c.row_factory = sqlite3.Row
        return c

    def _init(self) -> None:
        c = self._conn()
        try:
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA synchronous=NORMAL")
            c.executescript("""
                CREATE TABLE IF NOT EXISTS verification_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    vuln_class TEXT NOT NULL,
                    method TEXT NOT NULL,
                    evidence_type TEXT,
                    outcome TEXT NOT NULL,            -- success | failure
                    evidence_strength REAL DEFAULT 0.0,
                    source_ids TEXT,                  -- json list of contributing source.ids
                    dedup_key TEXT,                   -- optional; UNIQUE → idempotent
                    occurred_at REAL NOT NULL,
                    UNIQUE(dedup_key)
                );
                CREATE INDEX IF NOT EXISTS idx_ve_class ON verification_events(vuln_class);
                CREATE INDEX IF NOT EXISTS idx_ve_method ON verification_events(method);
            """)
            c.commit()
        finally:
            c.close()

    # ── write (append-only, idempotent on dedup_key) ─────────────────────────
    def record_verification(self, vuln_class: str, method: str, outcome: str,
                            evidence_type: str = "", evidence_strength: float = 0.0,
                            source_ids: Optional[List[str]] = None,
                            dedup_key: Optional[str] = None) -> bool:
        """Append one verification event. Returns True iff newly recorded. A non-null
        `dedup_key` makes the record idempotent (retries/concurrent workers converge)."""
        if not vuln_class or not method:
            raise ValueError("vuln_class and method are required")
        if outcome not in (OUTCOME_SUCCESS, OUTCOME_FAILURE):
            raise ValueError(f"outcome must be success|failure, got {outcome!r}")
        c = self._conn()
        try:
            cur = c.execute(
                "INSERT OR IGNORE INTO verification_events (vuln_class, method, evidence_type, "
                "outcome, evidence_strength, source_ids, dedup_key, occurred_at) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (vuln_class, method, evidence_type, outcome, float(evidence_strength),
                 json.dumps(sorted(source_ids or [])), dedup_key, time.time()))
            c.commit()
            return cur.rowcount == 1
        finally:
            c.close()

    # ── read aggregation (single grouped queries) ────────────────────────────
    def _grouped(self, key: str, where: str = "", params: tuple = ()) -> List[Dict]:
        c = self._conn()
        try:
            rows = c.execute(
                f"SELECT {key} k, COUNT(*) attempts, "
                "SUM(outcome='success') successes, SUM(outcome='failure') failures, "
                "AVG(evidence_strength) strength FROM verification_events "
                f"{where} GROUP BY {key}", params).fetchall()
        finally:
            c.close()
        out = []
        for r in rows:
            ms = MethodStats(method=r["k"] or "", attempts=int(r["attempts"]),
                             successes=int(r["successes"] or 0), failures=int(r["failures"] or 0),
                             evidence_strength=float(r["strength"] or 0.0))
            d = ms.to_dict()
            d.pop("method", None)
            d[key] = r["k"]               # label the group by its actual key
            out.append(d)
        out.sort(key=lambda d: (-d["success_rate"], -d["attempts"], str(d.get(key))))
        return out

    def method_stats(self) -> List[Dict]:
        return self._grouped("method")

    def by_vuln_class(self) -> List[Dict]:
        return self._grouped("vuln_class")

    def by_evidence_type(self) -> List[Dict]:
        return self._grouped("evidence_type")

    def methods_for_class(self, vuln_class: str) -> List[Dict]:
        return self._grouped("method", "WHERE vuln_class = ?", (vuln_class,))

    def by_source_category(self, category_of: Dict[str, str]) -> List[Dict]:
        """Verification success aggregated by contributing-source CATEGORY. `category_of`
        maps source_id → category (from the capability registry; kept out of this store)."""
        c = self._conn()
        try:
            rows = c.execute("SELECT source_ids, outcome FROM verification_events").fetchall()
        finally:
            c.close()
        agg: Dict[str, Dict[str, int]] = {}
        for r in rows:
            try:
                sids = json.loads(r["source_ids"] or "[]")
            except Exception:
                sids = []
            cats = {category_of.get(s, "unknown") for s in sids} or {"unknown"}
            for cat in cats:
                a = agg.setdefault(cat, {"attempts": 0, "successes": 0})
                a["attempts"] += 1
                a["successes"] += 1 if r["outcome"] == OUTCOME_SUCCESS else 0
        out = [{"category": cat, **a,
                "success_rate": round((a["successes"] + 1) / (a["attempts"] + 2), 4)}
               for cat, a in agg.items()]
        out.sort(key=lambda d: (-d["success_rate"], -d["attempts"], d["category"]))
        return out

    def reset(self) -> None:
        c = self._conn()
        try:
            c.execute("DELETE FROM verification_events")
            c.commit()
        finally:
            c.close()


# ── Validation Intelligence (read-only, explainable, deterministic) ─────────────
class ValidationIntelligence:
    """Answers operator questions from the verification event log. Read-only."""

    def __init__(self, store: Optional[VerificationLearningStore] = None):
        self.store = store or VerificationLearningStore()

    def how_verified(self, vuln_class: str) -> List[Dict]:
        """Methods historically used to verify this class, ranked by success rate."""
        return self.store.methods_for_class(vuln_class)

    def most_predictive_evidence(self) -> List[Dict]:
        """Evidence types ranked by verification success rate (most predictive first)."""
        return self.store.by_evidence_type()

    def best_sequence(self, vuln_class: str) -> List[str]:
        """The ordered methods (highest success first) that work for this class."""
        return [m["method"] for m in self.store.methods_for_class(vuln_class)]

    def what_next(self, vuln_class: str, done: Optional[List[str]] = None) -> Optional[Dict]:
        """The highest-success method not yet tried for this verification."""
        done = set(done or [])
        for m in self.store.methods_for_class(vuln_class):
            if m["method"] not in done:
                return m
        return None

    def summary(self, category_of: Optional[Dict[str, str]] = None) -> Dict:
        return {
            "method_stats": self.store.method_stats(),
            "by_vuln_class": self.store.by_vuln_class(),
            "most_predictive_evidence": self.most_predictive_evidence(),
            "by_source_category": self.store.by_source_category(category_of or {}),
        }


# ── Verification Playbooks (advisory) ───────────────────────────────────────────
# Static default methods per vuln class so a playbook is useful from cold-start; they
# correspond to the modelled "Verification" tool category. Learned methods (from the
# event log) take precedence and are merged on top. Nothing here executes anything.
DEFAULT_VERIFICATION_METHODS: Dict[str, List[str]] = {
    "idor": ["idor_verifier", "auth_context_swap", "object_id_enumeration"],
    "ssrf": ["ssrf_verifier", "oob_callback", "internal_metadata_probe"],
    "open_redirect": ["open_redirect_verifier", "redirect_chain_trace"],
    "csrf": ["cors_verifier", "token_absence_check"],
    "auth_bypass": ["oauth_verifier", "jwt_verifier", "session_fixation_check"],
    "xss": ["reflection_probe", "dom_sink_trace", "csp_bypass_check"],
    "sqli": ["boolean_blind_probe", "error_based_probe", "time_based_probe"],
    "rce": ["oob_callback", "command_echo_probe"],
    "xxe": ["oob_xxe_probe", "file_read_probe"],
    "ssti": ["template_eval_probe", "oob_callback"],
}
_GENERIC_METHODS = ["evidence_replay", "two_signal_corroboration", "manual_review"]


def _normalize(vuln_class: str) -> str:
    return str(vuln_class or "").strip().lower().replace("-", "_").replace(" ", "_")


@dataclass
class PlaybookStep:
    method: str
    success_rate: float
    confidence: float
    expected_value: float
    source: str          # "learned" | "default"
    attempts: int = 0

    def to_dict(self) -> Dict:
        return {"method": self.method, "success_rate": self.success_rate,
                "confidence": self.confidence, "expected_value": self.expected_value,
                "source": self.source, "attempts": self.attempts}


@dataclass
class VerificationPlaybook:
    vuln_class: str
    steps: List[PlaybookStep] = field(default_factory=list)
    expected_verification_value: float = 0.0
    confidence_of_success: float = 0.0

    def to_dict(self) -> Dict:
        return {"vuln_class": self.vuln_class,
                "steps": [s.to_dict() for s in self.steps],
                "expected_verification_value": self.expected_verification_value,
                "confidence_of_success": self.confidence_of_success}


class VerificationPlaybookGenerator:
    """Generate a ranked, advisory verification playbook for a vulnerability class.

    Deterministic: learned methods (ranked by success rate) are merged with the static
    default catalog; the result is stable for a given event log. ADVISORY — it never
    executes a verification or confirms a finding."""

    def __init__(self, store: Optional[VerificationLearningStore] = None):
        self.store = store or VerificationLearningStore()

    def generate(self, vuln_class: str,
                 evidence_types: Optional[List[str]] = None) -> VerificationPlaybook:
        norm = _normalize(vuln_class)
        steps: List[PlaybookStep] = []
        seen: set = set()

        # 1. Learned methods for this class (highest success first).
        for m in self.store.methods_for_class(vuln_class):
            method = m["method"]
            if not method or method in seen:
                continue
            seen.add(method)
            ev = round(0.6 * m["success_rate"] + 0.4 * m["confidence"], 4)
            steps.append(PlaybookStep(method, m["success_rate"], m["confidence"], ev,
                                      "learned", m["attempts"]))

        # 2. Static defaults not yet covered (neutral priors).
        for method in DEFAULT_VERIFICATION_METHODS.get(norm, _GENERIC_METHODS):
            if method in seen:
                continue
            seen.add(method)
            steps.append(PlaybookStep(method, 0.5, 0.5, 0.5, "default", 0))

        # Deterministic ordering: expected_value desc, then method asc.
        steps.sort(key=lambda s: (-s.expected_value, s.method))

        if steps:
            wsum = sum(1.0 / (i + 1) for i in range(len(steps)))
            evv = round(sum(s.expected_value / (i + 1) for i, s in enumerate(steps)) / wsum, 4)
            cos = round(max(s.confidence for s in steps), 4)
        else:
            evv = cos = 0.0
        return VerificationPlaybook(vuln_class=norm, steps=steps,
                                    expected_verification_value=evv, confidence_of_success=cos)
