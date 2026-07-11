"""StreamHandler — streaming execution for all long-running operations.

Handles:
  - AI response streaming (token-by-token via callback)
  - Tool output streaming (chunk-by-chunk)
  - Generic operation streaming with progress tracking
"""

from __future__ import annotations

import threading
import time
from typing import Any, Callable, Iterator


class StreamHandler:
    """Delivers streaming output via callbacks — AI tokens, tool output, progress."""

    def __init__(self, callback: Callable[[str], None]):
        self._callback = callback
        self._cancelled = threading.Event()

    def cancel(self):
        self._cancelled.set()

    @property
    def is_cancelled(self) -> bool:
        return self._cancelled.is_set()

    # ── AI streaming ──

    def stream_text(self, text: str, chunk_size: int = 4):
        """Stream pre-generated text in chunks."""
        for i in range(0, len(text), chunk_size):
            if self._cancelled.is_set():
                break
            self._callback(text[i:i + chunk_size])

    async def stream_async(self, provider, messages: list[dict]) -> str:
        """Stream from an async provider, calling callback per token."""
        full_text = ""
        try:
            async for chunk in provider.astream(messages):
                if self._cancelled.is_set():
                    break
                full_text += chunk
                self._callback(chunk)
        except AttributeError:
            response = provider.chat(messages)
            full_text = response
            self.stream_text(response)
        return full_text

    def stream_sync(self, provider, messages: list[dict]) -> str:
        """Stream from a sync provider with streaming support."""
        full_text = ""
        try:
            for chunk in provider.stream(messages):
                if self._cancelled.is_set():
                    break
                full_text += chunk
                self._callback(chunk)
        except AttributeError:
            response = provider.chat(messages)
            full_text = response
            self.stream_text(response)
        return full_text

    # ── Tool output streaming ──

    def stream_lines(self, lines: Iterator[str]):
        """Stream line-by-line output from a tool."""
        for line in lines:
            if self._cancelled.is_set():
                break
            self._callback(line)

    # ── Progress streaming ──

    def stream_progress(self, total: int, label: str = ""):
        """Return a progress callback that streams updates."""
        state = {"current": 0}

        def update(current: int | None = None, message: str = ""):
            if self._cancelled.is_set():
                return
            if current is not None:
                state["current"] = current
            else:
                state["current"] += 1
            pct = round(state["current"] / max(1, total) * 100)
            prefix = f"{label}: " if label else ""
            self._callback(f"{prefix}{pct}% ({state['current']}/{total}) {message}")

        return update


class OperationStream:
    """Wraps any long-running operation with streaming output."""

    def __init__(self, event_bus, tool_name: str, target: str = ""):
        self._bus = event_bus
        self._tool = tool_name
        self._target = target
        self._tool_id = f"{tool_name}-{int(time.time())}"
        self._started = False

    def start(self):
        self._started = True
        self._bus.emit("tool.started", {
            "tool": self._tool,
            "target": self._target,
            "tool_id": self._tool_id,
        })

    def output(self, chunk: str):
        self._bus.emit("tool.output", {
            "tool": self._tool,
            "chunk": chunk,
            "tool_id": self._tool_id,
        })

    def complete(self, result: dict[str, Any] | None = None):
        self._bus.emit("tool.completed", {
            "tool": self._tool,
            "target": self._target,
            "tool_id": self._tool_id,
            "result": result or {},
        })

    def fail(self, error: str):
        self._bus.emit("tool.failed", {
            "tool": self._tool,
            "error": error,
            "tool_id": self._tool_id,
        })

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            self.fail(str(exc_val))
        else:
            self.complete()
        return False
