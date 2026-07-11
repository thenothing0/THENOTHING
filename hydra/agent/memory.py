"""Agent memory — four bounded stores, persisted with existing HYDRA storage.

  * WorkingMemory      — transient scratch key/values for the current run
  * ConversationMemory — user/agent turns
  * ExecutionMemory    — record of executed tasks + outcomes
  * KnowledgeMemory    — facts/observations gleaned from real outputs

Every store is bounded (deque ``maxlen``) so memory never grows without limit.
``AgentMemory`` aggregates them and round-trips to a JSON file under the data
directory so a session can resume after a restart. No third-party deps.
"""

from __future__ import annotations

import json
from collections import deque
from pathlib import Path
from typing import Any

WORKING_MAX = 200
CONVERSATION_MAX = 500
EXECUTION_MAX = 1000
KNOWLEDGE_MAX = 1000


class _BoundedList:
    """A bounded, JSON-serialisable append store."""

    def __init__(self, maxlen: int, items: list | None = None):
        self._dq: deque = deque(items or [], maxlen=maxlen)

    def add(self, item: Any) -> None:
        self._dq.append(item)

    def all(self) -> list:
        return list(self._dq)

    def recent(self, n: int = 10) -> list:
        return list(self._dq)[-n:]

    def clear(self) -> None:
        self._dq.clear()

    def __len__(self) -> int:
        return len(self._dq)


class AgentMemory:
    """Aggregate of the four bounded memory stores for one agent session."""

    def __init__(self, session_id: str = "", data_dir: str | Path = "data"):
        self.session_id = session_id
        self._data_dir = Path(data_dir)
        self.working: dict[str, Any] = {}
        self.conversation = _BoundedList(CONVERSATION_MAX)
        self.execution = _BoundedList(EXECUTION_MAX)
        self.knowledge = _BoundedList(KNOWLEDGE_MAX)

    # ── Working memory ──

    def set(self, key: str, value: Any) -> None:
        if key not in self.working and len(self.working) >= WORKING_MAX:
            # Drop an arbitrary oldest-ish key to stay bounded.
            self.working.pop(next(iter(self.working)), None)
        self.working[key] = value

    def get(self, key: str, default: Any = None) -> Any:
        return self.working.get(key, default)

    # ── Conversation / execution / knowledge ──

    def add_message(self, role: str, text: str) -> None:
        self.conversation.add({"role": role, "text": text})

    def record_execution(self, task_id: str, command: str, state: str,
                         error: str = "") -> None:
        self.execution.add({
            "task_id": task_id, "command": command, "state": state, "error": error,
        })

    def add_knowledge(self, source: str, fact: Any) -> None:
        self.knowledge.add({"source": source, "fact": fact})

    # ── Serialisation / persistence ──

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "working": dict(self.working),
            "conversation": self.conversation.all(),
            "execution": self.execution.all(),
            "knowledge": self.knowledge.all(),
        }

    def load_dict(self, data: dict[str, Any]) -> None:
        self.session_id = data.get("session_id", self.session_id)
        self.working = dict(data.get("working", {}))
        self.conversation = _BoundedList(CONVERSATION_MAX, data.get("conversation", []))
        self.execution = _BoundedList(EXECUTION_MAX, data.get("execution", []))
        self.knowledge = _BoundedList(KNOWLEDGE_MAX, data.get("knowledge", []))

    @classmethod
    def from_dict(cls, data: dict[str, Any], data_dir: str | Path = "data") -> AgentMemory:
        mem = cls(session_id=data.get("session_id", ""), data_dir=data_dir)
        mem.load_dict(data)
        return mem

    def _path(self) -> Path:
        return self._data_dir / "agent" / f"{self.session_id or 'default'}.json"

    def save(self) -> bool:
        try:
            path = self._path()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(self.to_dict(), default=str), encoding="utf-8")
            return True
        except Exception:
            return False

    def resume(self) -> bool:
        """Reload this session's memory from disk if present."""
        try:
            path = self._path()
            if path.exists():
                self.load_dict(json.loads(path.read_text(encoding="utf-8")))
                return True
        except Exception:
            pass
        return False
