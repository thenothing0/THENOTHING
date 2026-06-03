"""
SourceLearningStore — event-sourced source-performance learning (Phase D).

Builds on the C.5 `SourceMetricsStore` idea but makes it a real learning system:
**every score is a pure, deterministic function of an append-only event log**, so the
whole thing is trivially rebuildable and reproducible.

Architectural position (unchanged invariants):
  * **Derived, NOT canonical.** Lives under `data/` (gitignored). The wiki never reads
    or mirrors it → **no dual-write**. Wipe and recompute any time.
  * **Keyed by the stable `source.id`** for source events; outcome events are keyed by
    candidate signature/id. Renames never break history.
  * **Pure scoring.** `trust/novelty/effectiveness` are Laplace-smoothed functions of
    aggregated counts — same events ⇒ identical scores. `confidence.py` is untouched.

Two event streams:
  * `source_events`  — recon-source performance (discovery / confirmed / duplicate /
    rejected / pattern_created / chain_contribution).
  * `outcome_events` — candidate outcomes (confirmed / rejected) with signature +
    evidence-class combo, powering knowledge-guided prioritization.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

_DEFAULT_DB = Path(__file__).resolve().parents[2] / "data" / "source_learning.db"

# Source event vocabulary.
EV_DISCOVERY = "discovery"
EV_CONFIRMED = "confirmed_finding"
EV_DUPLICATE = "duplicate_finding"
EV_REJECTED = "rejected_candidate"
EV_PATTERN = "pattern_created"
EV_CHAIN = "chain_contribution"
_POSITIVE = {EV_CONFIRMED, EV_PATTERN, EV_CHAIN}

OUTCOME_CONFIRMED = "confirmed"
OUTCOME_REJECTED = "rejected"


@dataclass
class SourceScores:
    source_id: str
    discoveries: int = 0
    confirmed_findings: int = 0
    duplicate_findings: int = 0
    rejected_candidates: int = 0
    unique_patterns_created: int = 0
    chain_contributions: int = 0
    last_success_at: Optional[float] = None

    # ── derived scores (pure functions of the counts above) ──────────────────
    @property
    def trust_score(self) -> float:
        # Laplace-smoothed confirm-vs-reject reputation → stable with little data.
        return round((self.confirmed_findings + 1) /
                     (self.confirmed_findings + self.rejected_candidates + 2), 4)

    @property
    def effectiveness_score(self) -> float:
        # Yield: how many discoveries became confirmed findings.
        if self.discoveries <= 0:
            return 0.0
        return round(min(1.0, self.confirmed_findings / self.discoveries), 4)

    @property
    def novelty_score(self) -> float:
        # New knowledge vs duplicates (Laplace-smoothed).
        new = self.unique_patterns_created + self.chain_contributions
        return round((new + 1) / (new + self.duplicate_findings + 2), 4)

    def to_dict(self) -> Dict:
        return {
            "source_id": self.source_id,
            "discoveries": self.discoveries,
            "confirmed_findings": self.confirmed_findings,
            "duplicate_findings": self.duplicate_findings,
            "rejected_candidates": self.rejected_candidates,
            "unique_patterns_created": self.unique_patterns_created,
            "chain_contributions": self.chain_contributions,
            "last_success_at": self.last_success_at,
            "trust_score": self.trust_score,
            "effectiveness_score": self.effectiveness_score,
            "novelty_score": self.novelty_score,
        }


class SourceLearningStore:
    def __init__(self, db_path: Optional[Path | str] = None):
        # Precedence: explicit arg > HYDRA_SOURCE_LEARNING_DB env (test isolation) > data/.
        self.db_path = Path(db_path) if db_path else Path(
            os.environ.get("HYDRA_SOURCE_LEARNING_DB") or _DEFAULT_DB)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(str(self.db_path), timeout=10)
        c.row_factory = sqlite3.Row
        return c

    def _init(self) -> None:
        c = self._conn()
        try:
            c.executescript("""
                CREATE TABLE IF NOT EXISTS source_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    value REAL DEFAULT 1.0,
                    occurred_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_se_src ON source_events(source_id);
                CREATE TABLE IF NOT EXISTS outcome_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    candidate_type TEXT NOT NULL,
                    candidate_id TEXT NOT NULL,
                    signature TEXT,
                    outcome TEXT NOT NULL,
                    evidence_combo TEXT,
                    occurred_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_oe_sig ON outcome_events(signature);
            """)
            c.commit()
        finally:
            c.close()

    # ── writes (append-only) ─────────────────────────────────────────────────
    def record_source_event(self, source_id: str, event_type: str, value: float = 1.0) -> None:
        if not source_id:
            raise ValueError("source_id is required (stable source.* id)")
        c = self._conn()
        try:
            c.execute("INSERT INTO source_events (source_id, event_type, value, occurred_at) "
                      "VALUES (?,?,?,?)", (source_id, event_type, float(value), time.time()))
            c.commit()
        finally:
            c.close()

    def record_outcome(self, candidate_type: str, candidate_id: str, outcome: str,
                       signature: str = "", evidence_combo: Optional[List[str]] = None) -> None:
        c = self._conn()
        try:
            c.execute("INSERT INTO outcome_events (candidate_type, candidate_id, signature, "
                      "outcome, evidence_combo, occurred_at) VALUES (?,?,?,?,?,?)",
                      (candidate_type, candidate_id, signature, outcome,
                       json.dumps(sorted(evidence_combo or [])), time.time()))
            c.commit()
        finally:
            c.close()

    # ── reads (pure aggregation → scores) ────────────────────────────────────
    def scores(self, source_id: str) -> SourceScores:
        c = self._conn()
        try:
            rows = c.execute("SELECT event_type, SUM(value) v, MAX(occurred_at) last "
                             "FROM source_events WHERE source_id=? GROUP BY event_type",
                             (source_id,)).fetchall()
            last_success = c.execute(
                "SELECT MAX(occurred_at) m FROM source_events WHERE source_id=? "
                "AND event_type IN (?,?,?)",
                (source_id, EV_CONFIRMED, EV_PATTERN, EV_CHAIN)).fetchone()["m"]
        finally:
            c.close()
        agg = {r["event_type"]: int(r["v"]) for r in rows}
        return SourceScores(
            source_id=source_id,
            discoveries=agg.get(EV_DISCOVERY, 0),
            confirmed_findings=agg.get(EV_CONFIRMED, 0),
            duplicate_findings=agg.get(EV_DUPLICATE, 0),
            rejected_candidates=agg.get(EV_REJECTED, 0),
            unique_patterns_created=agg.get(EV_PATTERN, 0),
            chain_contributions=agg.get(EV_CHAIN, 0),
            last_success_at=last_success,
        )

    def all_scores(self) -> List[SourceScores]:
        c = self._conn()
        try:
            ids = [r["source_id"] for r in c.execute(
                "SELECT DISTINCT source_id FROM source_events ORDER BY source_id").fetchall()]
        finally:
            c.close()
        return [self.scores(s) for s in ids]

    # ── knowledge-guided prioritization (read-only) ──────────────────────────
    def successful_patterns(self) -> List[Dict]:
        """Signatures ranked by historical acceptance (confirmed vs rejected)."""
        return self._outcome_breakdown("signature")

    def accepted_evidence_combos(self) -> List[Dict]:
        """Evidence-class combinations ranked by historical acceptance rate."""
        return self._outcome_breakdown("evidence_combo")

    def _outcome_breakdown(self, key: str) -> List[Dict]:
        c = self._conn()
        try:
            rows = c.execute(
                f"SELECT {key} k, "
                "SUM(outcome='confirmed') confirmed, SUM(outcome='rejected') rejected "
                f"FROM outcome_events GROUP BY {key}").fetchall()
        finally:
            c.close()
        out = []
        for r in rows:
            conf, rej = int(r["confirmed"] or 0), int(r["rejected"] or 0)
            total = conf + rej
            out.append({key: r["k"], "confirmed": conf, "rejected": rej,
                        "acceptance_rate": round(conf / total, 4) if total else 0.0})
        # deterministic: acceptance desc, confirmed desc, key asc
        out.sort(key=lambda d: (-d["acceptance_rate"], -d["confirmed"], str(d[key])))
        return out

    def effective_source_types(self, category_of: Dict[str, str]) -> List[Dict]:
        """Per source CATEGORY: aggregate confirmed-finding yield. `category_of` maps
        source_id → category (from the capability registry; kept out of this store to
        avoid coupling)."""
        agg: Dict[str, Dict[str, int]] = {}
        for s in self.all_scores():
            cat = category_of.get(s.source_id, "unknown")
            a = agg.setdefault(cat, {"confirmed": 0, "discoveries": 0, "rejected": 0})
            a["confirmed"] += s.confirmed_findings
            a["discoveries"] += s.discoveries
            a["rejected"] += s.rejected_candidates
        out = []
        for cat, a in agg.items():
            d = a["discoveries"]
            out.append({"category": cat, **a,
                        "yield": round(a["confirmed"] / d, 4) if d else 0.0})
        out.sort(key=lambda d: (-d["yield"], -d["confirmed"], d["category"]))
        return out

    # ── lifecycle (derived ⇒ disposable) ─────────────────────────────────────
    def reset(self) -> None:
        c = self._conn()
        try:
            c.executescript("DELETE FROM source_events; DELETE FROM outcome_events;")
            c.commit()
        finally:
            c.close()
