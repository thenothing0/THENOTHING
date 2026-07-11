"""AI Session — manages conversation state with an AI provider.

This is the single interface the rest of HYDRA uses for AI interactions.
The Facade and PresentationAPI delegate here; no widget talks to LLM directly.
"""

from __future__ import annotations

import logging
from typing import Any

from hydra.ai.context import ContextManager
from hydra.ai.providers import ProviderManager
from hydra.services.event_bus import EventBus

logger = logging.getLogger("hydra.ai.session")


class AISession:
    """Manages a conversation session with an AI provider."""

    def __init__(
        self,
        provider_manager: ProviderManager,
        context_manager: ContextManager,
        event_bus: EventBus,
    ):
        self._pm = provider_manager
        self._cm = context_manager
        self._bus = event_bus
        self._history: list[dict[str, str]] = []
        self._system_contexts: list[str] = []

    # ── Conversation ──

    def send(self, message: str, stream: bool = True) -> str:
        """Send a message and get a response."""
        self._history.append({"role": "user", "content": message})
        self._bus.emit("ai.message_sent", {"role": "user", "length": len(message)})

        try:
            provider = self._pm.get_active_client()
            if provider is None:
                response = "(No AI provider configured)"
            else:
                messages = self._build_messages()
                response = provider.chat(messages)

            self._history.append({"role": "assistant", "content": response})
            self._bus.emit("ai.message_received", {"role": "assistant", "length": len(response)})
            return response
        except Exception as e:
            logger.exception("AI send failed")
            error_msg = f"AI error: {e}"
            self._bus.emit("ai.error", {"error": str(e)})
            return error_msg

    def add_system_context(self, context: str):
        """Inject persistent system context (engagement, scope, etc.)."""
        self._system_contexts.append(context)

    def clear_system_context(self):
        self._system_contexts.clear()

    def get_history(self) -> list[dict[str, str]]:
        return list(self._history)

    def compact(self):
        """Reduce history to fit context window."""
        self._history = self._cm.compact(self._history, target_tokens=4000)
        self._bus.emit("ai.compacted", {"messages": len(self._history)})

    def clear(self):
        """Reset conversation history."""
        self._history.clear()
        self._bus.emit("ai.cleared")

    # ── Provider management ──

    def switch_provider(self, provider_id: str):
        self._pm.switch(provider_id)
        self._bus.emit("ai.provider_changed", {"provider": provider_id})

    def switch_model(self, model: str):
        self._pm.set_model(model)
        self._bus.emit("ai.model_changed", {"model": model})

    def get_info(self) -> dict[str, Any]:
        """Current provider, model, context usage."""
        active = self._pm.get_active_info()
        return {
            "provider": active.get("id", ""),
            "model": active.get("model", ""),
            "messages": len(self._history),
            "context_used": self._cm.estimate_tokens(self._history),
            "context_max": active.get("context_max", 0),
        }

    # ── Internal ──

    def _build_messages(self) -> list[dict[str, str]]:
        messages = []
        if self._system_contexts:
            messages.append({
                "role": "system",
                "content": "\n\n".join(self._system_contexts),
            })
        messages.extend(self._history)
        return messages
