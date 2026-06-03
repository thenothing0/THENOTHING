"""
PluginLoader (Phase M) — offline, declarative plugin discovery.

Reads plugin YAML files from a directory (default `hydra/plugins/packs/`) into
PluginDefinition objects. File reads ONLY — no execution, no network, no import of plugin
code (there is none). Deterministic ordering by plugin_id.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional

from hydra.plugins.plugin_validator import PluginDefinition

try:
    import yaml
except Exception:  # pragma: no cover
    yaml = None

_DEFAULT_PACKS = Path(__file__).resolve().parent / "packs"


def _to_definition(data: dict, source_path: str = "") -> PluginDefinition:
    return PluginDefinition(
        plugin_id=str(data.get("plugin_id", "")),
        plugin_name=str(data.get("plugin_name", "")),
        version=str(data.get("version", "0.0.0")),
        author=str(data.get("author", "")),
        description=str(data.get("description", "")),
        capabilities=list(data.get("capabilities") or []),
        adapters=list(data.get("adapters") or []),
        agents=list(data.get("agents") or []),
        dependencies=list(data.get("dependencies") or []),
        requires_plugins=list(data.get("requires_plugins") or []),
        source_path=source_path)


class PluginLoader:
    def __init__(self, plugin_dir: Optional[Path | str] = None):
        # Precedence: explicit arg > HYDRA_PLUGIN_DIR env (test isolation) > bundled packs.
        self.plugin_dir = Path(plugin_dir) if plugin_dir else Path(
            os.environ.get("HYDRA_PLUGIN_DIR") or _DEFAULT_PACKS)

    def discover(self) -> List[PluginDefinition]:
        if yaml is None or not self.plugin_dir.exists():
            return []
        out: List[PluginDefinition] = []
        for f in sorted(self.plugin_dir.glob("*.yaml")):
            try:
                data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
            except Exception:
                continue
            if isinstance(data, dict) and data.get("plugin_id"):
                out.append(_to_definition(data, source_path=str(f)))
        out.sort(key=lambda p: p.plugin_id)
        return out

    def load_file(self, path: Path | str) -> Optional[PluginDefinition]:
        path = Path(path)
        if yaml is None or not path.exists():
            return None
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return _to_definition(data, source_path=str(path)) if data.get("plugin_id") else None
