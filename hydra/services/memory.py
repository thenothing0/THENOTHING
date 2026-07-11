"""Cyber Memory Service — similarity-based recall of security knowledge.

Provides structured search, recall, and recording of security-relevant
memories: attack outcomes, reasoning traces, verified patterns, and
cross-engagement lessons. Wraps kb_recall, attack_memory, and the
learning service into a unified memory interface.
"""

import json
import logging
import time
from typing import Any

from hydra.services.base import BaseService

logger = logging.getLogger("hydra.services.memory")


class MemoryService(BaseService):
    """Unified cyber memory: recall, record, and search security knowledge."""

    def recall(self, query: str, *, types: str = "", target: str = "",
               limit: int = 10) -> list[dict]:
        """Recall relevant memories using keyword + graph-proximity search."""
        results = []
        kb_results = self._kb_recall(query, types=types, target=target, limit=limit)
        results.extend(kb_results)
        attack_results = self._attack_memory_search(query, limit=limit)
        results.extend(attack_results)
        lesson_results = self._lesson_search(query, limit=limit)
        results.extend(lesson_results)
        results.sort(key=lambda r: r.get("score", 0), reverse=True)
        self._emit("memory.recalled", {
            "query": query[:100],
            "result_count": len(results),
        })
        return results[:limit]

    def record(self, kind: str, content: str, *,
               target: str = "", metadata: dict | None = None) -> dict:
        """Record a memory entry."""
        entry = {
            "ts": time.time(),
            "kind": kind,
            "content": content[:2000],
            "target": target,
            "metadata": metadata or {},
        }
        try:
            self._append_to_memory(entry)
            self._emit("memory.recorded", {
                "kind": kind, "target": target,
            })
            return {"status": "ok", "kind": kind}
        except Exception as e:
            logger.error("record failed: %s", e)
            return {"status": "error", "error": str(e)}

    def record_outcome(self, target: str, vuln_class: str,
                       outcome: str, evidence: str = "") -> dict:
        """Record an attack outcome for future recall."""
        return self.record(
            kind="attack_outcome",
            content=f"{vuln_class}: {outcome}",
            target=target,
            metadata={
                "vuln_class": vuln_class,
                "outcome": outcome,
                "evidence": evidence[:500],
            },
        )

    def record_reasoning(self, target: str, trace: list[str],
                         skills: list[str] | None = None) -> dict:
        """Record a reasoning trace."""
        try:
            from hydra.skills.attack_memory import append_reasoning_trace
            append_reasoning_trace(target, trace, skills or [])
            self._emit("memory.reasoning_recorded", {"target": target})
            return {"status": "ok", "steps": len(trace)}
        except ImportError:
            return self.record(
                kind="reasoning_trace",
                content="\n".join(trace[:20]),
                target=target,
                metadata={"skills": skills or []},
            )

    def get_recent(self, *, limit: int = 20, kind: str = "") -> list[dict]:
        """Get recent memory entries."""
        try:
            from hydra.skills.attack_memory import tail_events
            events = tail_events(max_lines=limit)
            if kind:
                events = [e for e in events if e.get("kind") == kind]
            return events[:limit]
        except ImportError:
            return self._read_memory_file(limit=limit, kind=kind)

    def search_by_target(self, target: str, *, limit: int = 20) -> list[dict]:
        """Search memories related to a specific target."""
        results = []
        kb = self._kb_recall(target, target=target, limit=limit)
        results.extend(kb)
        attack = self._attack_memory_search(target, limit=limit)
        results.extend([e for e in attack if target.lower() in str(e).lower()])
        return results[:limit]

    def search_by_vuln_class(self, vuln_class: str, *, limit: int = 20) -> list[dict]:
        """Search memories related to a vulnerability class."""
        return self.recall(vuln_class, types="finding,pattern,technique", limit=limit)

    def get_stats(self) -> dict[str, Any]:
        """Memory system statistics."""
        try:
            recent = self.get_recent(limit=1000)
            kinds: dict[str, int] = {}
            for e in recent:
                k = e.get("kind", "unknown")
                kinds[k] = kinds.get(k, 0) + 1
            return {
                "total_entries": len(recent),
                "by_kind": kinds,
            }
        except Exception:
            return {"total_entries": 0, "by_kind": {}}

    # ── Internal search methods ──

    def _kb_recall(self, query: str, *, types: str = "",
                   target: str = "", limit: int = 10) -> list[dict]:
        try:
            from hydra.knowledge.wiki_store import WikiStore
            store = WikiStore()
            results = store.recall(query, types=types, target=target, limit=limit)
            return [
                {
                    "source": "knowledge_base",
                    "slug": r.get("slug", ""),
                    "title": r.get("title", ""),
                    "type": r.get("type", ""),
                    "score": r.get("score", 0),
                    "snippet": r.get("snippet", ""),
                }
                for r in results
            ] if results else []
        except Exception:
            return []

    def _attack_memory_search(self, query: str, limit: int = 10) -> list[dict]:
        try:
            from hydra.skills.attack_memory import tail_events
            events = tail_events(max_lines=200)
            query_lower = query.lower()
            matched = []
            for e in events:
                content = json.dumps(e).lower()
                if query_lower in content:
                    e["source"] = "attack_memory"
                    e["score"] = 0.5
                    matched.append(e)
            return matched[:limit]
        except (ImportError, Exception):
            return []

    def _lesson_search(self, query: str, limit: int = 10) -> list[dict]:
        try:
            from hydra.services.learning import LearningService
            svc = LearningService(self._bus, self._data_dir)
            results = svc.search(query, limit=limit)
            return [
                {
                    "source": "lessons",
                    "title": r.get("title", ""),
                    "category": r.get("category", ""),
                    "lesson": r.get("lesson", "")[:200],
                    "score": r.get("score", 0.3),
                }
                for r in results
            ] if results else []
        except Exception:
            return []

    def _append_to_memory(self, entry: dict) -> None:
        memory_file = self._data_dir / "cyber_memory.jsonl"
        memory_file.parent.mkdir(parents=True, exist_ok=True)
        with open(memory_file, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def _read_memory_file(self, *, limit: int = 20, kind: str = "") -> list[dict]:
        memory_file = self._data_dir / "cyber_memory.jsonl"
        if not memory_file.exists():
            return []
        try:
            entries = []
            for line in memory_file.read_text().strip().split("\n"):
                if line:
                    e = json.loads(line)
                    if not kind or e.get("kind") == kind:
                        entries.append(e)
            return entries[-limit:]
        except Exception:
            return []
