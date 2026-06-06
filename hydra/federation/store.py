"""
KnowledgeExchangeStore (Phase N) — event-sourced federation ledger.

Append-only SQLite log under `data/federation.db` (WAL). Every federation fact —
peer announcements, exported digests, imported digests — is an immutable event.
All federation intelligence is a pure function of this log, so the store is fully
rebuildable & disposable. Idempotent via a UNIQUE `exchange_id` (derived from the
content when not supplied), so re-importing the same digest is a no-op.

Stores AGGREGATED METADATA ONLY: every write is guarded by `assert_safe()`, which
rejects wiki pages, evidence, findings, targets, source identities and secrets.
Never touches the canonical wiki / promotion.py / confidence.py.

Grouped-aggregation reads only (single pass / GROUP BY) → O(E), never O(N²).
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Dict, List, Optional

from hydra.federation.safety import assert_safe, canonical_json, deterministic_id

_DEFAULT_DB = Path(__file__).resolve().parents[2] / "data" / "federation.db"

EV_PEER = "peer_announcement"
EV_DIGEST_EXPORT = "digest_export"
EV_DIGEST_IMPORT = "digest_import"
_EVENT_TYPES = (EV_PEER, EV_DIGEST_EXPORT, EV_DIGEST_IMPORT)


class KnowledgeExchangeStore:
    def __init__(self, db_path: Optional[Path | str] = None):
        # Precedence: explicit arg > HYDRA_FEDERATION_DB env (test isolation) > data/.
        self.db_path = Path(db_path) if db_path else Path(
            os.environ.get("HYDRA_FEDERATION_DB") or _DEFAULT_DB)
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
                CREATE TABLE IF NOT EXISTS federation_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    exchange_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    peer_id TEXT NOT NULL DEFAULT '',
                    payload TEXT NOT NULL DEFAULT '{}',
                    occurred_at REAL NOT NULL,
                    UNIQUE(exchange_id)
                );
                CREATE INDEX IF NOT EXISTS idx_fe_type ON federation_events(event_type);
                CREATE INDEX IF NOT EXISTS idx_fe_peer ON federation_events(peer_id);
            """)
            c.commit()
        finally:
            c.close()

    # ── write (append-only, idempotent, metadata-guarded) ───────────────────────
    def record(self, event_type: str, payload: Optional[Dict] = None, peer_id: str = "",
               exchange_id: Optional[str] = None, occurred_at: Optional[float] = None) -> bool:
        """Append a federation event. Returns True if inserted, False if deduped.

        `payload` is validated to be aggregated metadata only (no raw knowledge).
        `exchange_id`, when omitted, is derived from the content → idempotent."""
        if event_type not in _EVENT_TYPES:
            raise ValueError(f"event_type must be one of {_EVENT_TYPES}, got {event_type!r}")
        payload = payload or {}
        assert_safe(payload, where=f"{event_type} payload")
        body = canonical_json(payload)
        if exchange_id is None:
            exchange_id = deterministic_id("xchg", event_type, peer_id, body)
        ts = float(occurred_at) if occurred_at is not None else time.time()
        c = self._conn()
        try:
            cur = c.execute(
                "INSERT OR IGNORE INTO federation_events "
                "(exchange_id, event_type, peer_id, payload, occurred_at) VALUES (?,?,?,?,?)",
                (exchange_id, event_type, peer_id, body, ts))
            c.commit()
            return cur.rowcount == 1
        finally:
            c.close()

    # ── grouped reads (O(E)) ────────────────────────────────────────────────────
    def latest_peer_announcements(self) -> List[Dict]:
        """Most-recent announcement payload per peer (single pass, O(E))."""
        c = self._conn()
        try:
            rows = c.execute(
                "SELECT peer_id, payload, occurred_at FROM federation_events "
                "WHERE event_type=? ORDER BY occurred_at, id", (EV_PEER,)).fetchall()
        finally:
            c.close()
        latest: Dict[str, Dict] = {}
        for r in rows:                      # ascending → last write per peer wins
            latest[r["peer_id"]] = {"peer_id": r["peer_id"],
                                    "payload": json.loads(r["payload"]),
                                    "last_seen": r["occurred_at"]}
        return [latest[k] for k in sorted(latest)]

    def import_counts_by_peer(self) -> Dict[str, int]:
        c = self._conn()
        try:
            rows = c.execute(
                "SELECT peer_id, COUNT(*) n FROM federation_events "
                "WHERE event_type=? GROUP BY peer_id", (EV_DIGEST_IMPORT,)).fetchall()
        finally:
            c.close()
        return {r["peer_id"]: int(r["n"]) for r in rows}

    def imported_digests(self) -> List[Dict]:
        """Parsed payloads of every imported digest envelope, in ingest order."""
        c = self._conn()
        try:
            rows = c.execute(
                "SELECT payload FROM federation_events WHERE event_type=? "
                "ORDER BY occurred_at, id", (EV_DIGEST_IMPORT,)).fetchall()
        finally:
            c.close()
        return [json.loads(r["payload"]) for r in rows]

    def counts_by_type(self) -> Dict[str, int]:
        c = self._conn()
        try:
            rows = c.execute(
                "SELECT event_type, COUNT(*) n FROM federation_events GROUP BY event_type"
            ).fetchall()
        finally:
            c.close()
        return {r["event_type"]: int(r["n"]) for r in rows}

    def summary(self) -> Dict:
        by_type = self.counts_by_type()
        return {
            "total_events": sum(by_type.values()),
            "events_by_type": dict(sorted(by_type.items())),
            "distinct_peers": len(self.latest_peer_announcements()),
            "imported_digests": by_type.get(EV_DIGEST_IMPORT, 0),
            "exported_digests": by_type.get(EV_DIGEST_EXPORT, 0),
        }

    def reset(self) -> None:
        c = self._conn()
        try:
            c.execute("DELETE FROM federation_events")
            c.commit()
        finally:
            c.close()
