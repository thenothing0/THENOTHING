"""
PluginDefinition + PluginValidator (Phase M).

A plugin is a purely DECLARATIVE bundle (YAML → data): capabilities, capability dependency
edges, optional agent declarations, and optional plugin version dependencies. It contains
NO executable code. The validator enforces that invariant (only JSON-serializable scalars/
lists/dicts), checks the schema, semver, duplicate capability ids, and dependency targets.

Read-only / pure: validation never executes a plugin, accesses the network, or mutates
anything. promotion.py / confidence.py are untouched.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

_SEMVER = re.compile(r"^\d+\.\d+\.\d+$")
_ID = re.compile(r"^[a-z0-9][a-z0-9_]*$")
_VALID_RELATIONS = ("requires", "enhances", "related_to")
# Keys that would imply executable/dynamic behavior — forbidden in a declarative plugin.
_FORBIDDEN_KEYS = {"exec", "eval", "code", "script", "shell", "command", "entrypoint",
                   "python", "run", "subprocess", "import"}


@dataclass
class PluginDefinition:
    plugin_id: str
    plugin_name: str = ""
    version: str = "0.0.0"
    author: str = ""
    description: str = ""
    capabilities: List[Dict] = field(default_factory=list)
    adapters: List[Dict] = field(default_factory=list)
    agents: List[Dict] = field(default_factory=list)
    dependencies: List[Dict] = field(default_factory=list)     # capability edges
    requires_plugins: List[Dict] = field(default_factory=list)  # {plugin_id, min_version}
    source_path: str = ""

    @property
    def capability_ids(self) -> List[str]:
        return [str(c.get("id")) for c in self.capabilities if c.get("id")]

    @property
    def tools(self) -> List[str]:
        return sorted({t for c in self.capabilities for t in (c.get("tools") or [])})

    @property
    def verification_coverage(self) -> int:
        return sum(int(c.get("verification_coverage", 0) or 0) for c in self.capabilities)

    def to_dict(self) -> Dict:
        return {
            "plugin_id": self.plugin_id, "plugin_name": self.plugin_name,
            "version": self.version, "author": self.author, "description": self.description,
            "capability_count": len(self.capabilities), "capability_ids": sorted(self.capability_ids),
            "tool_count": len(self.tools), "agent_count": len(self.agents),
            "dependency_count": len(self.dependencies),
            "verification_coverage": self.verification_coverage,
            "requires_plugins": self.requires_plugins,
        }


def _is_declarative(value) -> bool:
    """True iff value is a tree of JSON-ish scalars/lists/dicts (no code objects)."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return True
    if isinstance(value, (list, tuple)):
        return all(_is_declarative(v) for v in value)
    if isinstance(value, dict):
        return all(isinstance(k, str) and _is_declarative(v) for k, v in value.items())
    return False


class PluginValidator:
    def validate(self, pd: PluginDefinition,
                 existing_capability_ids: Optional[set] = None) -> List[str]:
        """Return a list of error strings (empty ⇒ valid). Deterministic & pure."""
        errors: List[str] = []
        existing = set(existing_capability_ids or set())

        if not pd.plugin_id or not _ID.match(pd.plugin_id):
            errors.append(f"invalid plugin_id: {pd.plugin_id!r}")
        if not _SEMVER.match(pd.version or ""):
            errors.append(f"invalid version (need MAJOR.MINOR.PATCH): {pd.version!r}")

        seen: set = set()
        for c in pd.capabilities:
            cid = c.get("id")
            if not cid or not _ID.match(str(cid)):
                errors.append(f"invalid capability id: {cid!r}")
                continue
            if not c.get("category"):
                errors.append(f"capability {cid} missing category")
            if cid in seen:
                errors.append(f"duplicate capability id within plugin: {cid}")
            seen.add(cid)
            if cid in existing:
                errors.append(f"capability id already declared elsewhere (globally unique): {cid}")
            if not _is_declarative(c):
                errors.append(f"capability {cid} contains non-declarative content")
            for k in c:
                if str(k).lower() in _FORBIDDEN_KEYS:
                    errors.append(f"capability {cid} has forbidden key '{k}' (no executable code)")

        # dependency edges must reference known ids (plugin caps + existing) and valid relation
        known = seen | existing
        for e in pd.dependencies:
            rel = e.get("relation")
            if rel not in _VALID_RELATIONS:
                errors.append(f"invalid dependency relation: {rel!r}")
            for side in ("from", "to"):
                ref = e.get(side)
                if ref and ref not in known and rel == "requires":
                    # requires-edges must resolve within plugin+existing scope
                    errors.append(f"dependency {side} references unknown capability: {ref}")

        if not _is_declarative({"a": pd.agents, "b": pd.dependencies, "c": pd.requires_plugins}):
            errors.append("plugin contains non-declarative content")
        return errors

    def check_version_compat(self, pd: PluginDefinition,
                             installed: Dict[str, str]) -> List[str]:
        """Errors for unmet plugin version dependencies. `installed` maps plugin_id→version."""
        errors: List[str] = []
        for dep in pd.requires_plugins:
            pid, minv = dep.get("plugin_id"), dep.get("min_version", "0.0.0")
            if pid not in installed:
                errors.append(f"missing required plugin: {pid}")
            elif _SEMVER.match(installed[pid] or "") and _SEMVER.match(minv or "") \
                    and _ver(installed[pid]) < _ver(minv):
                errors.append(f"plugin {pid} {installed[pid]} < required {minv}")
        return errors


def _ver(v: str) -> tuple:
    return tuple(int(x) for x in v.split("."))
