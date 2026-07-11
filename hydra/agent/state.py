"""AgentStateMachine — thread-safe, observable agent lifecycle.

Guards the ``AgentState`` transitions, notifies observers on change, and (when
given an EventBus) emits ``agent.state`` events. Uses an RLock so it is safe to
drive from a background worker thread while the UI observes it.
"""

from __future__ import annotations

import threading
from typing import Callable

from hydra.agent.models import TERMINAL_AGENT_STATES, AgentState

# Allowed forward transitions. Terminal states may reset to IDLE for reuse.
_ALLOWED: dict[AgentState, frozenset[AgentState]] = {
    AgentState.IDLE: frozenset({AgentState.PLANNING, AgentState.CANCELLED}),
    AgentState.PLANNING: frozenset({
        AgentState.EXECUTING, AgentState.COMPLETED, AgentState.FAILED,
        AgentState.CANCELLED,
    }),
    AgentState.EXECUTING: frozenset({
        AgentState.WAITING, AgentState.REFLECTING, AgentState.COMPLETED,
        AgentState.FAILED, AgentState.CANCELLED,
    }),
    AgentState.WAITING: frozenset({
        AgentState.EXECUTING, AgentState.REFLECTING, AgentState.FAILED,
        AgentState.CANCELLED,
    }),
    AgentState.REFLECTING: frozenset({
        AgentState.PLANNING, AgentState.EXECUTING, AgentState.COMPLETED,
        AgentState.FAILED, AgentState.CANCELLED,
    }),
    AgentState.COMPLETED: frozenset({AgentState.IDLE}),
    AgentState.FAILED: frozenset({AgentState.IDLE}),
    AgentState.CANCELLED: frozenset({AgentState.IDLE}),
}

Observer = Callable[[AgentState, AgentState], None]


class AgentStateMachine:
    """Thread-safe, observable state machine for the agent lifecycle."""

    def __init__(self, initial: AgentState = AgentState.IDLE, event_bus=None):
        self._state = initial
        self._lock = threading.RLock()
        self._observers: list[Observer] = []
        self._bus = event_bus

    @property
    def state(self) -> AgentState:
        with self._lock:
            return self._state

    def is_terminal(self) -> bool:
        with self._lock:
            return self._state in TERMINAL_AGENT_STATES

    def can_transition(self, to: AgentState) -> bool:
        with self._lock:
            return to in _ALLOWED.get(self._state, frozenset())

    def transition(self, to: AgentState) -> bool:
        """Attempt a transition. Returns True if it was allowed and applied."""
        with self._lock:
            if to not in _ALLOWED.get(self._state, frozenset()):
                return False
            old, self._state = self._state, to
            observers = list(self._observers)
        for cb in observers:
            try:
                cb(old, to)
            except Exception:
                pass
        if self._bus is not None:
            try:
                self._bus.emit("agent.state", {"from": old.value, "to": to.value})
            except Exception:
                pass
        return True

    def force(self, to: AgentState) -> None:
        """Unconditionally set the state (used for restore). Notifies observers."""
        with self._lock:
            old, self._state = self._state, to
            observers = list(self._observers)
        for cb in observers:
            try:
                cb(old, to)
            except Exception:
                pass

    def reset(self) -> None:
        self.force(AgentState.IDLE)

    def on_change(self, callback: Observer) -> None:
        with self._lock:
            self._observers.append(callback)
