"""Provider management — hot-swappable providers with dynamic model discovery.

Capabilities:
  - Auto-discover providers from SecretStore (not raw env vars)
  - Hot-swap provider/model at runtime without restart
  - Dynamic model discovery per provider
  - Health monitoring: latency, availability, rate limits
  - Provider metadata: supported models, context windows, capabilities
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

logger = logging.getLogger("hydra.ai.providers")

_PROVIDER_CATALOG: dict[str, dict[str, Any]] = {
    "anthropic": {
        "name": "Anthropic",
        "secret_key": "anthropic_api_key",
        "default_model": "claude-sonnet-4",
        "models": {
            "claude-opus-4": {"context": 200000, "output": 32000},
            "claude-sonnet-4": {"context": 200000, "output": 16000},
            "claude-haiku-4": {"context": 200000, "output": 8000},
        },
        "base_url": "https://api.anthropic.com",
    },
    "openai": {
        "name": "OpenAI",
        "secret_key": "openai_api_key",
        "default_model": "gpt-4o",
        "models": {
            "gpt-4o": {"context": 128000, "output": 16384},
            "gpt-4o-mini": {"context": 128000, "output": 16384},
            "gpt-4-turbo": {"context": 128000, "output": 4096},
            "o3-mini": {"context": 200000, "output": 100000},
        },
        "base_url": "https://api.openai.com",
    },
    "google": {
        "name": "Google AI",
        "secret_key": "google_api_key",
        "default_model": "gemini-2.5-pro",
        "models": {
            "gemini-2.5-pro": {"context": 1000000, "output": 65536},
            "gemini-2.5-flash": {"context": 1000000, "output": 65536},
        },
        "base_url": "https://generativelanguage.googleapis.com",
    },
}


class ProviderHealth:
    """Tracks per-provider health metrics."""

    __slots__ = (
        "last_check", "available", "latency_ms", "error_count",
        "rate_limited_until", "last_error",
    )

    def __init__(self):
        self.last_check: float = 0
        self.available: bool = False
        self.latency_ms: float = 0
        self.error_count: int = 0
        self.rate_limited_until: float = 0
        self.last_error: str = ""

    def record_success(self, latency_ms: float):
        self.last_check = time.time()
        self.available = True
        self.latency_ms = latency_ms
        self.error_count = 0
        self.last_error = ""

    def record_failure(self, error: str):
        self.last_check = time.time()
        self.error_count += 1
        self.last_error = error
        if self.error_count >= 3:
            self.available = False

    def record_rate_limit(self, retry_after: float = 60):
        self.rate_limited_until = time.time() + retry_after
        self.last_error = "rate_limited"

    @property
    def is_rate_limited(self) -> bool:
        return time.time() < self.rate_limited_until

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": self.available and not self.is_rate_limited,
            "latency_ms": round(self.latency_ms, 1),
            "error_count": self.error_count,
            "rate_limited": self.is_rate_limited,
            "last_error": self.last_error,
            "last_check": self.last_check,
        }


class ProviderManager:
    """Hot-swappable provider management with health tracking."""

    def __init__(self):
        self._lock = threading.Lock()
        self._active_id: str = ""
        self._active_model: str = ""
        self._health: dict[str, ProviderHealth] = {}
        self._custom_models: dict[str, dict[str, dict]] = {}

        self._discover()

    # ── Discovery ──

    def _discover(self):
        """Auto-discover providers from SecretStore."""
        try:
            from hydra.config.secrets import SecretStore
            store = SecretStore.get()
        except ImportError:
            store = None

        for pid, catalog in _PROVIDER_CATALOG.items():
            secret_key = catalog["secret_key"]
            has_key = False
            if store:
                has_key = store.has_secret(secret_key)
            else:
                import os
                env_var = secret_key.upper()
                has_key = os.environ.get(env_var) is not None

            if has_key:
                self._health[pid] = ProviderHealth()
                self._health[pid].available = True

        if not self._active_id and self._health:
            self._active_id = next(iter(self._health))
            info = _PROVIDER_CATALOG[self._active_id]
            self._active_model = info["default_model"]

    def rediscover(self):
        """Re-scan for providers (after credential hot-swap)."""
        with self._lock:
            self._discover()

    # ── Provider listing ──

    def list_providers(self) -> list[dict[str, Any]]:
        result = []
        for pid, catalog in _PROVIDER_CATALOG.items():
            health = self._health.get(pid)
            result.append({
                "id": pid,
                "name": catalog["name"],
                "available": health.available if health else False,
                "active": pid == self._active_id,
                "models": list(catalog["models"].keys()),
                "health": health.to_dict() if health else None,
            })
        return result

    def get_active_info(self) -> dict[str, Any]:
        if self._active_id in _PROVIDER_CATALOG:
            catalog = _PROVIDER_CATALOG[self._active_id]
            model_info = catalog["models"].get(self._active_model, {})
            health = self._health.get(self._active_id)
            return {
                "id": self._active_id,
                "name": catalog["name"],
                "model": self._active_model,
                "context_max": model_info.get("context", 200000),
                "output_max": model_info.get("output", 8000),
                "health": health.to_dict() if health else None,
            }
        return {"id": "", "model": "", "context_max": 0}

    # ── Hot-swap ──

    def switch(self, provider_id: str):
        if provider_id not in _PROVIDER_CATALOG:
            raise ValueError(f"Unknown provider: {provider_id}")
        with self._lock:
            self._active_id = provider_id
            catalog = _PROVIDER_CATALOG[provider_id]
            self._active_model = catalog["default_model"]
            if provider_id not in self._health:
                self._health[provider_id] = ProviderHealth()
                self._health[provider_id].available = True

    def set_model(self, model: str):
        with self._lock:
            self._active_model = model

    # ── Model discovery ──

    def discover_models(self, provider_id: str | None = None) -> list[dict[str, Any]]:
        """Return available models for a provider (static catalog + custom)."""
        pid = provider_id or self._active_id
        if pid not in _PROVIDER_CATALOG:
            return []
        catalog = _PROVIDER_CATALOG[pid]
        models = []
        for mid, info in catalog["models"].items():
            models.append({
                "id": mid,
                "context": info.get("context", 0),
                "output": info.get("output", 0),
                "active": mid == self._active_model and pid == self._active_id,
                "source": "catalog",
            })
        for mid, info in self._custom_models.get(pid, {}).items():
            models.append({
                "id": mid,
                "context": info.get("context", 0),
                "output": info.get("output", 0),
                "active": mid == self._active_model and pid == self._active_id,
                "source": "custom",
            })
        return models

    def add_custom_model(self, provider_id: str, model_id: str, context: int = 128000, output: int = 8000):
        if provider_id not in self._custom_models:
            self._custom_models[provider_id] = {}
        self._custom_models[provider_id][model_id] = {"context": context, "output": output}

    # ── Health monitoring ──

    def record_success(self, provider_id: str | None = None, latency_ms: float = 0):
        pid = provider_id or self._active_id
        if pid in self._health:
            self._health[pid].record_success(latency_ms)

    def record_failure(self, error: str, provider_id: str | None = None):
        pid = provider_id or self._active_id
        if pid in self._health:
            self._health[pid].record_failure(error)

    def record_rate_limit(self, retry_after: float = 60, provider_id: str | None = None):
        pid = provider_id or self._active_id
        if pid in self._health:
            self._health[pid].record_rate_limit(retry_after)

    def get_health(self, provider_id: str | None = None) -> dict[str, Any]:
        pid = provider_id or self._active_id
        h = self._health.get(pid)
        return h.to_dict() if h else {"available": False}

    def get_all_health(self) -> dict[str, dict[str, Any]]:
        return {pid: h.to_dict() for pid, h in self._health.items()}

    # ── Client ──

    def get_active_client(self):
        if not self._active_id:
            return None
        health = self._health.get(self._active_id)
        if health and health.is_rate_limited:
            logger.warning("Provider %s is rate-limited", self._active_id)
            return None
        try:
            from hydra.ai.router import get_client
            return get_client(self._active_id, self._active_model)
        except Exception:
            logger.debug("Could not create LLM client for %s", self._active_id)
            return None

    def health_check(self, provider_id: str) -> bool:
        h = self._health.get(provider_id)
        return h.available if h else False
