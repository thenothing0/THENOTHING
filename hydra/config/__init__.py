"""Central configuration — profiles, secrets, runtime settings."""

from hydra.config.manager import ConfigManager, ConfigProfile
from hydra.config.secrets import SecretStore

# Bridge: hydra/config.py (standalone module) is shadowed by this package.
# Load it explicitly and re-export so `from hydra.config import get_config` works.
import importlib.util as _ilu
from pathlib import Path as _Path

_legacy_path = str(_Path(__file__).parent.parent / "config.py")
_spec = _ilu.spec_from_file_location("hydra._config_legacy", _legacy_path)
if _spec and _spec.loader:
    _legacy = _ilu.module_from_spec(_spec)
    _spec.loader.exec_module(_legacy)
    # Re-export all public symbols from the legacy module
    for _name in dir(_legacy):
        if not _name.startswith("_") and _name not in globals():
            globals()[_name] = getattr(_legacy, _name)
    del _legacy

del _ilu, _Path, _legacy_path, _spec

__all__ = [
    "ConfigManager", "ConfigProfile", "SecretStore",
    "get_config", "HydraConfig",
    "BASE_DIR", "DATA_DIR", "LOGS_DIR", "RESULTS_DIR", "REPORTS_DIR", "WORDLISTS_DIR",
]
