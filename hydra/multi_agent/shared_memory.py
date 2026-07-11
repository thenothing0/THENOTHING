"""SharedMemory — thread-safe, bounded blackboard for the agent team.

Holds the current goal, findings, knowledge, reasoning, per-agent outputs,
confidence scores and execution history. Every store is bounded (deque
``maxlen``) so memory never grows without limit. All access is guarded by an
RLock so specialist agents can read/write concurrently.
"""

from __future__ import annotations

import threading
from collections import deque
from typing import Any

from hydra.multi_agent.models import Finding

FINDINGS_MAX = 1000
KNOWLEDGE_MAX = 1000
REASONING_MAX = 1000
HISTORY_MAX = 2000
OUTPUTS_MAX = 1000


class SharedMemory:
    """A bounded, thread-safe shared blackboard."""

    def __init__(self):
        self._lock = threading.RLock()
        self.goal: str = ""
        self.target: str = ""
        self._findings: deque[Finding] = deque(maxlen=FINDINGS_MAX)
        self._knowledge: deque[dict] = deque(maxlen=KNOWLEDGE_MAX)
        self._reasoning: deque[dict] = deque(maxlen=REASONING_MAX)
        self._outputs: deque[dict] = deque(maxlen=OUTPUTS_MAX)
        self._history: deque[dict] = deque(maxlen=HISTORY_MAX)
        self._confidence: dict[str, float] = {}

    # ── Goal ──

    def set_goal(self, goal: str, target: str = "") -> None:
        with self._lock:
            self.goal = goal
            self.target = target

    # ── Findings ──

    def add_finding(self, finding: Finding) -> None:
        with self._lock:
            self._findings.append(finding)

    def findings(self) -> list[Finding]:
        with self._lock:
            return list(self._findings)

    # ── Knowledge ──

    def add_knowledge(self, source: str, item: Any) -> None:
        with self._lock:
            self._knowledge.append({"source": source, "item": item})

    def knowledge(self) -> list[dict]:
        with self._lock:
            return list(self._knowledge)

    # ── Reasoning ──

    def add_reasoning(self, agent_id: str, thought: str) -> None:
        with self._lock:
            self._reasoning.append({"agent": agent_id, "thought": thought})

    def reasoning(self) -> list[dict]:
        with self._lock:
            return list(self._reasoning)

    # ── Agent outputs ──

    def record_output(self, agent_id: str, task_id: str, output: Any) -> None:
        with self._lock:
            self._outputs.append({"agent": agent_id, "task_id": task_id, "output": output})

    def outputs(self) -> list[dict]:
        with self._lock:
            return list(self._outputs)

    # ── Execution history ──

    def record_execution(self, agent_id: str, command: str, state: str,
                         error: str = "") -> None:
        with self._lock:
            self._history.append({
                "agent": agent_id, "command": command, "state": state, "error": error,
            })

    def history(self) -> list[dict]:
        with self._lock:
            return list(self._history)

    # ── Confidence ──

    def set_confidence(self, key: str, value: float) -> None:
        with self._lock:
            self._confidence[key] = value

    def get_confidence(self, key: str, default: float = 0.0) -> float:
        with self._lock:
            return self._confidence.get(key, default)

    # ── Summary / serialisation ──

    def summary(self) -> dict[str, Any]:
        with self._lock:
            return {
                "goal": self.goal,
                "target": self.target,
                "findings": len(self._findings),
                "knowledge": len(self._knowledge),
                "reasoning": len(self._reasoning),
                "outputs": len(self._outputs),
                "history": len(self._history),
            }

    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            return {
                "goal": self.goal,
                "target": self.target,
                "findings": [f.to_dict() for f in self._findings],
                "knowledge": list(self._knowledge),
                "reasoning": list(self._reasoning),
                "outputs": list(self._outputs),
                "history": list(self._history),
                "confidence": dict(self._confidence),
            }

    def load_dict(self, data: dict[str, Any]) -> None:
        with self._lock:
            self.goal = data.get("goal", "")
            self.target = data.get("target", "")
            self._findings = deque(
                (Finding.from_dict(f) for f in data.get("findings", [])), maxlen=FINDINGS_MAX)
            self._knowledge = deque(data.get("knowledge", []), maxlen=KNOWLEDGE_MAX)
            self._reasoning = deque(data.get("reasoning", []), maxlen=REASONING_MAX)
            self._outputs = deque(data.get("outputs", []), maxlen=OUTPUTS_MAX)
            self._history = deque(data.get("history", []), maxlen=HISTORY_MAX)
            self._confidence = dict(data.get("confidence", {}))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SharedMemory:
        mem = cls()
        mem.load_dict(data)
        return mem
