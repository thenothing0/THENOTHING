"""
EventBus — lightweight in-process publish/subscribe.

All state changes in HYDRA flow through this bus. Services publish events
after completing operations. The Presentation API subscribes and forwards
to the renderer. No polling anywhere.
"""

import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

from hydra.observability.telemetry import telemetry as _telemetry

logger = logging.getLogger("hydra.services.event_bus")

_EMPTY: dict = {}


@dataclass
class Event:
    type: str
    payload: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    source: str = ""


class EventBus:
    """Thread-safe in-process event bus."""

    def __init__(self):
        self._subscribers: dict[str, dict[str, Callable]] = {}
        self._prefix_subscribers: dict[str, dict[str, Callable]] = {}
        self._wildcard_subscribers: dict[str, Callable] = {}
        self._lock = threading.Lock()

    def publish(self, event: Event) -> None:
        callbacks = []
        with self._lock:
            if event.type in self._subscribers:
                callbacks.extend(self._subscribers[event.type].values())
            for pattern, subs in self._prefix_subscribers.items():
                if event.type.startswith(pattern):
                    callbacks.extend(subs.values())
            callbacks.extend(self._wildcard_subscribers.values())

        for cb in callbacks:
            try:
                cb(event)
            except Exception:
                logger.exception("event handler failed for %s", event.type)

    def emit(self, event_type: str, payload: dict[str, Any] | None = None,
             source: str = "") -> None:
        _telemetry.counter("events.total")
        _telemetry.counter(f"events.{event_type}")
        self.publish(Event(type=event_type, payload=payload if payload is not None else _EMPTY, source=source))

    def subscribe(self, event_type: str, callback: Callable) -> str:
        sub_id = str(uuid.uuid4())
        with self._lock:
            if event_type == "*":
                self._wildcard_subscribers[sub_id] = callback
            elif event_type.endswith(".*"):
                prefix = event_type[:-1]  # "test.*" → "test."
                if prefix not in self._prefix_subscribers:
                    self._prefix_subscribers[prefix] = {}
                self._prefix_subscribers[prefix][sub_id] = callback
            else:
                if event_type not in self._subscribers:
                    self._subscribers[event_type] = {}
                self._subscribers[event_type][sub_id] = callback
        return sub_id

    def unsubscribe(self, sub_id: str) -> None:
        with self._lock:
            self._wildcard_subscribers.pop(sub_id, None)
            for subs in self._subscribers.values():
                subs.pop(sub_id, None)
            for subs in self._prefix_subscribers.values():
                subs.pop(sub_id, None)

    def clear(self) -> None:
        with self._lock:
            self._subscribers.clear()
            self._prefix_subscribers.clear()
            self._wildcard_subscribers.clear()
