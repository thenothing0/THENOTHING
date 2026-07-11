"""ConfigManager — central configuration with profile support.

Profiles: development, testing, production, offline, cloud.
Config is loaded from (lowest to highest priority):
  1. Built-in defaults
  2. Profile defaults
  3. config.yaml (project-level)
  4. ~/.hydra/config.yaml (user-level)
  5. Environment variables (HYDRA_*)
  6. Runtime overrides
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger("hydra.config")


class ConfigProfile(str, Enum):
    DEVELOPMENT = "development"
    TESTING = "testing"
    PRODUCTION = "production"
    OFFLINE = "offline"
    CLOUD = "cloud"


_PROFILE_DEFAULTS: dict[str, dict[str, Any]] = {
    "development": {
        "log_level": "DEBUG",
        "data_dir": "data",
        "rate_limit": 5.0,
        "stealth_mode": False,
        "auto_save_interval": 30,
        "max_workers": 4,
        "event_buffer_size": 1000,
        "ai.default_provider": "anthropic",
        "ai.default_model": "claude-sonnet-4",
        "ai.context_max": 200000,
        "ai.stream": True,
        "plugins.auto_load": True,
        "plugins.dirs": ["plugins", "hydra/plugins"],
        "session.auto_save": True,
        "session.crash_recovery": True,
        "tui.theme": "dark",
        "tui.sidebar_visible": True,
        "tui.bottom_panel_height": 12,
        "updates.check_on_start": False,
    },
    "testing": {
        "log_level": "WARNING",
        "data_dir": "test_data",
        "rate_limit": 100.0,
        "stealth_mode": False,
        "auto_save_interval": 0,
        "max_workers": 2,
        "event_buffer_size": 100,
        "ai.default_provider": "",
        "ai.default_model": "",
        "ai.context_max": 4000,
        "ai.stream": False,
        "plugins.auto_load": False,
        "plugins.dirs": [],
        "session.auto_save": False,
        "session.crash_recovery": False,
        "tui.theme": "dark",
        "tui.sidebar_visible": True,
        "tui.bottom_panel_height": 8,
        "updates.check_on_start": False,
    },
    "production": {
        "log_level": "INFO",
        "data_dir": "data",
        "rate_limit": 2.0,
        "stealth_mode": True,
        "auto_save_interval": 60,
        "max_workers": 8,
        "event_buffer_size": 5000,
        "ai.default_provider": "anthropic",
        "ai.default_model": "claude-sonnet-4",
        "ai.context_max": 200000,
        "ai.stream": True,
        "plugins.auto_load": True,
        "plugins.dirs": ["plugins", "hydra/plugins"],
        "session.auto_save": True,
        "session.crash_recovery": True,
        "tui.theme": "dark",
        "tui.sidebar_visible": True,
        "tui.bottom_panel_height": 12,
        "updates.check_on_start": True,
    },
    "offline": {
        "log_level": "INFO",
        "data_dir": "data",
        "rate_limit": 0.0,
        "stealth_mode": False,
        "auto_save_interval": 60,
        "max_workers": 4,
        "event_buffer_size": 1000,
        "ai.default_provider": "",
        "ai.default_model": "",
        "ai.context_max": 0,
        "ai.stream": False,
        "plugins.auto_load": True,
        "plugins.dirs": ["plugins"],
        "session.auto_save": True,
        "session.crash_recovery": True,
        "tui.theme": "dark",
        "tui.sidebar_visible": True,
        "tui.bottom_panel_height": 12,
        "updates.check_on_start": False,
    },
    "cloud": {
        "log_level": "INFO",
        "data_dir": "/var/hydra/data",
        "rate_limit": 10.0,
        "stealth_mode": True,
        "auto_save_interval": 30,
        "max_workers": 16,
        "event_buffer_size": 10000,
        "ai.default_provider": "anthropic",
        "ai.default_model": "claude-sonnet-4",
        "ai.context_max": 200000,
        "ai.stream": True,
        "plugins.auto_load": True,
        "plugins.dirs": ["plugins", "/etc/hydra/plugins"],
        "session.auto_save": True,
        "session.crash_recovery": True,
        "tui.theme": "dark",
        "tui.sidebar_visible": False,
        "tui.bottom_panel_height": 16,
        "updates.check_on_start": True,
    },
}

_DEFAULTS = _PROFILE_DEFAULTS["development"]


@dataclass
class _ConfigState:
    profile: ConfigProfile = ConfigProfile.DEVELOPMENT
    values: dict[str, Any] = field(default_factory=dict)
    overrides: dict[str, Any] = field(default_factory=dict)
    frozen: bool = False


class ConfigManager:
    """Thread-safe, profile-aware configuration manager.

    Access: ``cfg.get("ai.default_model")``
    Set at runtime: ``cfg.set("ai.stream", False)``
    Switch profile: ``cfg.set_profile(ConfigProfile.PRODUCTION)``
    """

    _instance: ConfigManager | None = None

    def __init__(self, profile: ConfigProfile | str | None = None):
        resolved = self._resolve_profile(profile)
        self._state = _ConfigState(
            profile=resolved,
            values=dict(_PROFILE_DEFAULTS.get(resolved.value, _DEFAULTS)),
        )
        self._load_file_config()
        self._load_env_overrides()

    # ── Singleton access ──

    @classmethod
    def get(cls) -> ConfigManager:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls):
        cls._instance = None

    # ── Read ──

    def __getitem__(self, key: str) -> Any:
        return self.get_value(key)

    def get_value(self, key: str, default: Any = None) -> Any:
        if key in self._state.overrides:
            return self._state.overrides[key]
        return self._state.values.get(key, default)

    @property
    def profile(self) -> ConfigProfile:
        return self._state.profile

    @property
    def data_dir(self) -> Path:
        return Path(self.get_value("data_dir", "data"))

    def as_dict(self) -> dict[str, Any]:
        merged = dict(self._state.values)
        merged.update(self._state.overrides)
        merged["_profile"] = self._state.profile.value
        return merged

    # ── Write ──

    def set(self, key: str, value: Any):
        if self._state.frozen:
            raise RuntimeError("Config is frozen")
        self._state.overrides[key] = value

    def set_profile(self, profile: ConfigProfile | str):
        if isinstance(profile, str):
            profile = ConfigProfile(profile)
        self._state.profile = profile
        base = dict(_PROFILE_DEFAULTS.get(profile.value, _DEFAULTS))
        base.update(self._state.overrides)
        self._state.values = base
        self._load_env_overrides()

    def freeze(self):
        self._state.frozen = True

    # ── Internal ──

    @staticmethod
    def _resolve_profile(profile: ConfigProfile | str | None) -> ConfigProfile:
        if profile is None:
            env = os.environ.get("HYDRA_PROFILE", "development")
            try:
                return ConfigProfile(env)
            except ValueError:
                return ConfigProfile.DEVELOPMENT
        if isinstance(profile, str):
            return ConfigProfile(profile)
        return profile

    def _load_file_config(self):
        for path in [Path("config.yaml"), Path.home() / ".hydra" / "config.yaml"]:
            if path.exists():
                try:
                    import yaml
                    with open(path) as f:
                        data = yaml.safe_load(f) or {}
                    self._state.values.update(self._flatten(data))
                except ImportError:
                    import json
                    json_path = path.with_suffix(".json")
                    if json_path.exists():
                        with open(json_path) as f:
                            data = json.load(f)
                        self._state.values.update(self._flatten(data))
                except Exception as e:
                    logger.warning("Failed to load config from %s: %s", path, e)

    def _load_env_overrides(self):
        prefix = "HYDRA_"
        for key, value in os.environ.items():
            if key.startswith(prefix) and key != "HYDRA_PROFILE":
                config_key = key[len(prefix):].lower().replace("__", ".")
                self._state.values[config_key] = self._coerce(value)

    @staticmethod
    def _flatten(d: dict, prefix: str = "") -> dict[str, Any]:
        items: dict[str, Any] = {}
        for k, v in d.items():
            key = f"{prefix}{k}" if not prefix else f"{prefix}.{k}"
            if isinstance(v, dict):
                items.update(ConfigManager._flatten(v, key))
            else:
                items[key] = v
        return items

    @staticmethod
    def _coerce(value: str) -> Any:
        if value.lower() in ("true", "yes", "1"):
            return True
        if value.lower() in ("false", "no", "0"):
            return False
        try:
            return int(value)
        except ValueError:
            pass
        try:
            return float(value)
        except ValueError:
            pass
        return value
