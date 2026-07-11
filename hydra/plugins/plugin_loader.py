"""
PluginLoader (Phase M) — offline, declarative plugin discovery.

Reads plugin YAML files from multiple directories into PluginDefinition objects.
File reads ONLY — no execution, no network, no import of plugin code (there is none).
Deterministic ordering by plugin_id.

Discovery directories (all optional):
  1. hydra/plugins/packs/   — bundled
  2. ~/.hydra/plugins/      — user-installed
  3. <project>/.hydra/plugins/ — project-local
  4. HYDRA_PLUGIN_DIR env   — test isolation override

Hot-reload: call `has_changes()` to detect new/modified/removed YAML files since
the last `discover()` without re-parsing everything.
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
        env_dir = os.environ.get("HYDRA_PLUGIN_DIR")
        if plugin_dir:
            self._dirs = [Path(plugin_dir)]
        elif env_dir:
            self._dirs = [Path(env_dir)]
        else:
            self._dirs = self._default_dirs()

        # Backwards compat
        self.plugin_dir = self._dirs[0] if self._dirs else _DEFAULT_PACKS
        # Snapshot for change detection: {path_str: mtime}
        self._snapshot: dict[str, float] = {}

    @staticmethod
    def _default_dirs() -> list[Path]:
        dirs = [_DEFAULT_PACKS]
        user_dir = Path.home() / ".hydra" / "plugins"
        if user_dir.is_dir():
            dirs.append(user_dir)
        project_dir = Path(".hydra") / "plugins"
        if project_dir.is_dir() and project_dir.resolve() != user_dir.resolve():
            dirs.append(project_dir)
        return dirs

    def _scan_files(self) -> dict[str, float]:
        """Return {path: mtime} for all .yaml files across all plugin dirs."""
        files: dict[str, float] = {}
        for d in self._dirs:
            if not d.exists():
                continue
            for f in d.glob("*.yaml"):
                try:
                    files[str(f)] = f.stat().st_mtime
                except OSError:
                    pass
        return files

    def discover(self) -> List[PluginDefinition]:
        if yaml is None:
            return []
        out: List[PluginDefinition] = []
        seen_ids: set[str] = set()
        new_snapshot: dict[str, float] = {}

        for d in self._dirs:
            if not d.exists():
                continue
            for f in sorted(d.glob("*.yaml")):
                try:
                    new_snapshot[str(f)] = f.stat().st_mtime
                    data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
                except Exception:
                    continue
                pid = data.get("plugin_id", "") if isinstance(data, dict) else ""
                if pid and pid not in seen_ids:
                    seen_ids.add(pid)
                    out.append(_to_definition(data, source_path=str(f)))

        self._snapshot = new_snapshot
        out.sort(key=lambda p: p.plugin_id)
        return out

    def has_changes(self) -> bool:
        """Check if any plugin files were added, removed, or modified since last discover()."""
        current = self._scan_files()
        return current != self._snapshot

    def load_file(self, path: Path | str) -> Optional[PluginDefinition]:
        path = Path(path)
        if yaml is None or not path.exists():
            return None
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return _to_definition(data, source_path=str(path)) if data.get("plugin_id") else None
