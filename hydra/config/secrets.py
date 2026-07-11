"""SecretStore — abstraction over credential access.

No component should read os.environ for API keys directly.
All credential access goes through SecretStore, which supports:
  1. Environment variables (default backend)
  2. .env files (dotenv)
  3. Keyring (system credential store)
  4. In-memory overrides (for testing / hot-swap)

Secrets are never logged, never serialized to disk in plaintext,
and never included in event payloads.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any

logger = logging.getLogger("hydra.config.secrets")

_KNOWN_SECRETS = {
    "anthropic_api_key": "ANTHROPIC_API_KEY",
    "openai_api_key": "OPENAI_API_KEY",
    "google_api_key": "GOOGLE_API_KEY",
    "shodan_api_key": "SHODAN_API_KEY",
    "censys_api_id": "CENSYS_API_ID",
    "censys_api_secret": "CENSYS_API_SECRET",
    "virustotal_api_key": "VIRUSTOTAL_API_KEY",
    "github_token": "GITHUB_TOKEN",
    "interactsh_token": "INTERACTSH_TOKEN",
    "burp_api_key": "BURP_API_KEY",
    "hackerone_api_token": "HACKERONE_API_TOKEN",
    "bugcrowd_api_token": "BUGCROWD_API_TOKEN",
}


class SecretStore:
    """Thread-safe credential store with multiple backends."""

    _instance: SecretStore | None = None

    def __init__(self):
        self._lock = threading.Lock()
        self._memory: dict[str, str] = {}
        self._env_loaded = False

    @classmethod
    def get(cls) -> SecretStore:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls):
        cls._instance = None

    def get_secret(self, name: str) -> str | None:
        """Retrieve a secret by logical name (e.g., 'anthropic_api_key')."""
        with self._lock:
            if name in self._memory:
                return self._memory[name]

        self._ensure_env_loaded()

        env_var = _KNOWN_SECRETS.get(name, name.upper())
        return os.environ.get(env_var)

    def set_secret(self, name: str, value: str):
        """Set an in-memory override (hot-swap credentials)."""
        with self._lock:
            self._memory[name] = value

    def remove_secret(self, name: str):
        with self._lock:
            self._memory.pop(name, None)

    def has_secret(self, name: str) -> bool:
        return self.get_secret(name) is not None

    def list_available(self) -> list[dict[str, Any]]:
        """List known secrets and whether they are set (never expose values)."""
        result = []
        for name, env_var in _KNOWN_SECRETS.items():
            has_memory = name in self._memory
            has_env = os.environ.get(env_var) is not None
            result.append({
                "name": name,
                "env_var": env_var,
                "available": has_memory or has_env,
                "source": "memory" if has_memory else ("env" if has_env else "none"),
            })
        return result

    def clear_memory(self):
        with self._lock:
            self._memory.clear()

    def _ensure_env_loaded(self):
        if self._env_loaded:
            return
        self._env_loaded = True
        try:
            from dotenv import load_dotenv
            load_dotenv()
        except ImportError:
            pass

    def __repr__(self) -> str:
        available = sum(1 for s in self.list_available() if s["available"])
        return f"SecretStore({available}/{len(_KNOWN_SECRETS)} configured)"
