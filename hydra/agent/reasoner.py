"""Reasoner — the Observe→Think→Plan→Execute→Observe→Reflect thought stream.

Produces grounded :class:`ReasoningStep` entries that summarise REAL HYDRA
outputs and context — it never fabricates findings, counts, or results. The
orchestrator calls it at each phase; the log is bounded and streamed via events.
"""

from __future__ import annotations

from collections import deque
from typing import Any

from hydra.agent.models import Observation, ReasoningStep

REASONING_LOG_MAX = 500


class Reasoner:
    """Generates and stores grounded reasoning steps."""

    def __init__(self, event_bus=None, max_log: int = REASONING_LOG_MAX):
        self._bus = event_bus
        self._log: deque[ReasoningStep] = deque(maxlen=max_log)

    # ── Core ──

    def note(self, phase: str, message: str) -> ReasoningStep:
        step = ReasoningStep(phase=phase, thought=message)
        self._log.append(step)
        self._emit(step)
        return step

    def observe(self, source: str, data: Any) -> Observation:
        """Record a real observation and note a grounded summary of it."""
        obs = Observation(source=source, data=data)
        self.note("observe", f"Observed from {source}: {self.summarize(data)}")
        return obs

    # ── Phase helpers (grounded in real values) ──

    def think_plan(self, objective: str, target: str, task_count: int) -> ReasoningStep:
        tgt = target or "no explicit target"
        return self.note(
            "plan",
            f"Objective '{_short(objective)}' → {tgt}; decomposed into {task_count} task(s).",
        )

    def think_execute(self, command: str) -> ReasoningStep:
        return self.note("execute", f"Executing HYDRA command: {command}")

    def think_reflect(self, task_desc: str, success: bool, action: str) -> ReasoningStep:
        verdict = "succeeded" if success else "failed"
        return self.note("reflect", f"Task '{_short(task_desc)}' {verdict} → {action}.")

    # ── Summaries (never invent data) ──

    @staticmethod
    def summarize(data: Any) -> str:
        if data is None:
            return "no data"
        if isinstance(data, dict):
            keys = list(data.keys())
            shown = ", ".join(keys[:5])
            return f"dict with keys [{shown}]" if keys else "empty dict"
        if isinstance(data, (list, tuple, set)):
            return f"{len(data)} item(s)"
        if isinstance(data, str):
            return _short(data)
        return type(data).__name__

    # ── Access ──

    def steps(self) -> list[ReasoningStep]:
        return list(self._log)

    def recent(self, n: int = 20) -> list[ReasoningStep]:
        return list(self._log)[-n:]

    def clear(self) -> None:
        self._log.clear()

    def _emit(self, step: ReasoningStep) -> None:
        if self._bus is None:
            return
        try:
            self._bus.emit("agent.reasoning", {
                "phase": step.phase, "thought": step.thought, "timestamp": step.timestamp,
            })
        except Exception:
            pass


def _short(text: str, limit: int = 80) -> str:
    text = str(text).strip().replace("\n", " ")
    return text if len(text) <= limit else text[: limit - 1] + "…"
