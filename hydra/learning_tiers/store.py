"""4-tier learning store: poison-gated write, fenced retrieval, approval promotion."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

# Narrow → broad. Promotion only moves toward broader tiers.
TIER_ORDER = ("project", "personal", "cross", "org")
_STATUS = ("active", "quarantined", "rejected")
# Source-class trust priors (verified findings outrank passive observations).
_SOURCE_TRUST = {"confirmed_finding": 0.6, "verification": 0.5, "manual": 0.4,
                 "recon": 0.3, "tool_output": 0.25, "unknown": 0.2}
_WORD_RE = re.compile(r"[a-z0-9]{3,}")


@dataclass
class Lesson:
    id: str
    tier: str
    title: str
    category: str
    lesson: str
    triggers: List[str] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    status: str = "active"
    trust: float = 0.3
    source_class: str = "unknown"
    host_hash: str = ""           # provenance: hashed host (no target leakage)
    engagement_id: str = ""
    inject_hits: List[str] = field(default_factory=list)
    confirmations: int = 0
    created_at: str = ""


class LearningTiersStore:
    def __init__(self, db_path: str = ".thenothing/learning/lessons.db"):
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
                CREATE TABLE IF NOT EXISTS lessons (
                  id TEXT PRIMARY KEY, tier TEXT NOT NULL, title TEXT NOT NULL,
                  category TEXT NOT NULL, lesson TEXT NOT NULL,
                  triggers TEXT NOT NULL, technologies TEXT NOT NULL,
                  status TEXT NOT NULL DEFAULT 'active', trust REAL NOT NULL DEFAULT 0.3,
                  source_class TEXT NOT NULL DEFAULT 'unknown', host_hash TEXT,
                  engagement_id TEXT, inject_hits TEXT, confirmations INTEGER DEFAULT 0,
                  created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_lessons_tier_status ON lessons(tier, status);
                CREATE INDEX IF NOT EXISTS idx_lessons_category ON lessons(category);
                """
            )

    # ── write path (poison-gated) ────────────────────────────────────────────────
    def record(self, tier: str, title: str, category: str, lesson: str,
               triggers: Optional[List[str]] = None, technologies: Optional[List[str]] = None,
               source_class: str = "unknown", host: str = "", engagement_id: str = "") -> Dict:
        from hydra.safety import redact, scan_injection

        if tier not in TIER_ORDER:
            raise ValueError(f"unknown tier '{tier}'")
        blob = f"{title} {lesson} {' '.join(triggers or [])}"
        hits = [h.pattern for h in scan_injection(blob)]
        status = "quarantined" if hits else "active"
        host_hash = hashlib.sha256(host.encode()).hexdigest()[:16] if host else ""
        trust = _SOURCE_TRUST.get(source_class, 0.2)
        lid = f"L-{uuid.uuid4().hex[:12]}"
        with self._conn() as c:
            c.execute(
                """INSERT INTO lessons (id, tier, title, category, lesson, triggers, technologies,
                   status, trust, source_class, host_hash, engagement_id, inject_hits,
                   confirmations, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (lid, tier, redact(title), category, redact(lesson),
                 json.dumps(triggers or []), json.dumps(technologies or []),
                 status, trust, source_class, host_hash, engagement_id,
                 json.dumps(hits), 0, _now()))
        return {"id": lid, "tier": tier, "status": status, "inject_hits": hits, "trust": trust}

    # ── retrieval (fenced) ───────────────────────────────────────────────────────
    def search(self, query: str, tier: str = "all", k: int = 5,
               fence: bool = True) -> List[Dict]:
        """Token-overlap × recency × trust ranking over ACTIVE lessons only.
        Results are wrapped as untrusted data (TN-2) by default."""
        from hydra.safety import fence_untrusted

        q_tokens = set(_WORD_RE.findall(query.lower()))
        tiers = TIER_ORDER if tier == "all" else (tier,)
        rows: List[sqlite3.Row] = []
        with self._conn() as c:
            for t in tiers:
                rows += c.execute(
                    "SELECT * FROM lessons WHERE tier=? AND status='active'", (t,)).fetchall()
        now = time.time()
        scored = []
        for r in rows:
            text = f"{r['title']} {r['lesson']} {r['triggers']}".lower()
            overlap = len(q_tokens & set(_WORD_RE.findall(text)))
            if overlap == 0:
                continue
            age_days = max(0.0, (now - _parse(r["created_at"])) / 86400.0)
            recency = 0.25 * (0.5 ** (age_days / 14.0))   # 14-day half-life boost
            score = overlap + recency + float(r["trust"])
            body = r["lesson"]
            scored.append({
                "id": r["id"], "tier": r["tier"], "title": r["title"],
                "lesson": fence_untrusted(body, f"learned:{r['tier']}") if fence else body,
                "score": round(score, 3), "trust": round(float(r["trust"]), 3),
                "category": r["category"],
            })
        scored.sort(key=lambda x: x["score"], reverse=True)
        return scored[:k]

    # ── governance ──────────────────────────────────────────────────────────────
    def quarantined(self) -> List[Dict]:
        with self._conn() as c:
            return [{"id": r["id"], "title": r["title"], "tier": r["tier"],
                     "inject_hits": json.loads(r["inject_hits"] or "[]")}
                    for r in c.execute(
                        "SELECT * FROM lessons WHERE status='quarantined'").fetchall()]

    def approve(self, lesson_id: str) -> Dict:
        """Release a quarantined lesson (human decided it's benign)."""
        with self._conn() as c:
            c.execute("UPDATE lessons SET status='active', inject_hits='[]' WHERE id=?",
                      (lesson_id,))
        return {"id": lesson_id, "status": "active"}

    def reject(self, lesson_id: str) -> Dict:
        with self._conn() as c:
            c.execute("UPDATE lessons SET status='rejected' WHERE id=?", (lesson_id,))
        return {"id": lesson_id, "status": "rejected"}

    def confirm(self, lesson_id: str) -> Dict:
        """Operator confirmation raises trust (org promotion needs >=2)."""
        with self._conn() as c:
            c.execute("UPDATE lessons SET confirmations=confirmations+1, "
                      "trust=MIN(1.0, trust+0.15) WHERE id=?", (lesson_id,))
            r = c.execute("SELECT confirmations, trust FROM lessons WHERE id=?",
                          (lesson_id,)).fetchone()
        return {"id": lesson_id, "confirmations": r["confirmations"], "trust": round(r["trust"], 3)}

    def promote(self, lesson_id: str, to_tier: str) -> Dict:
        """Promote toward a broader tier. Must move forward in TIER_ORDER; never
        promote a quarantined lesson; org tier requires >=2 confirmations."""
        if to_tier not in TIER_ORDER:
            raise ValueError(f"unknown tier '{to_tier}'")
        with self._conn() as c:
            r = c.execute("SELECT tier, status, confirmations FROM lessons WHERE id=?",
                          (lesson_id,)).fetchone()
            if not r:
                raise KeyError(lesson_id)
            if r["status"] != "active":
                raise ValueError(f"cannot promote a {r['status']} lesson")
            if TIER_ORDER.index(to_tier) <= TIER_ORDER.index(r["tier"]):
                raise ValueError(f"promotion must broaden ({r['tier']} -> {to_tier} is not forward)")
            if to_tier == "org" and r["confirmations"] < 2:
                raise ValueError("org-tier promotion requires >=2 confirmations")
            c.execute("UPDATE lessons SET tier=? WHERE id=?", (to_tier, lesson_id))
        return {"id": lesson_id, "from": r["tier"], "to": to_tier}

    def stats(self) -> Dict:
        with self._conn() as c:
            by_tier = {r["tier"]: r["n"] for r in c.execute(
                "SELECT tier, COUNT(*) n FROM lessons WHERE status='active' GROUP BY tier")}
            quarantined = c.execute(
                "SELECT COUNT(*) n FROM lessons WHERE status='quarantined'").fetchone()["n"]
        return {"active_by_tier": by_tier, "quarantined": quarantined}


def _parse(ts: str) -> float:
    try:
        return time.mktime(time.strptime(ts, "%Y-%m-%dT%H:%M:%SZ"))
    except Exception:
        return 0.0


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time()))
