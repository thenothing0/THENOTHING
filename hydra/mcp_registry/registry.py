"""MCP server registry, discovery, tool validation, trust scoring, isolation."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Callable, Dict, List, Optional

# Isolation: cap an external MCP tool result BEFORE it is fully materialized
# (PentesterFlow M10 — a hostile server returning multi-GB content would OOM the
# process if buffered + json.dumps'd first). 128 KiB protects context AND process.
MAX_MCP_RESULT_BYTES = 128 * 1024
DEFAULT_CALL_TIMEOUT_S = 60

_TOOL_NAME_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]{0,63}$")

# ToolLister: server_name -> [ {name, description?, inputSchema?} , ... ]
ToolLister = Callable[[str], List[Dict]]


class ToolTrust:
    TRUSTED_SIGNED = "trusted-signed"      # operator-declared trusted server
    DECLARED_LOCAL = "declared-local"      # in the registry, local command
    DISCOVERED_UNKNOWN = "discovered-unknown"  # tool from an untrusted/unknown server


# Trust class of a server → trust level of its tools.
_SERVER_TRUST = {
    "trusted": ToolTrust.TRUSTED_SIGNED,
    "local": ToolTrust.DECLARED_LOCAL,
    "unknown": ToolTrust.DISCOVERED_UNKNOWN,
}


class DiscoveryError(RuntimeError):
    """Server not declared, or a discovered tool failed validation."""


def namespaced(server: str, tool: str) -> str:
    """Namespace an external tool so it can't shadow a core tool name."""
    return f"mcp:{server}:{tool}"


def bounded_result(content, cap: int = MAX_MCP_RESULT_BYTES) -> str:
    """Serialize an MCP tool result with a HARD byte cap applied incrementally,
    never materializing more than `cap`+overhead (M10 fix). Accepts str or any
    json-able object; truncates with a marker."""
    if isinstance(content, str):
        text = content
    else:
        try:
            text = json.dumps(content)
        except (TypeError, ValueError):
            text = str(content)
    if len(text) > cap:
        return text[:cap] + f"\n... [TRUNCATED — {len(text)} bytes from external MCP server]"
    return text


def validate_tool(tool: Dict, server: str, existing_names: set) -> Dict:
    """Validate a discovered tool. Returns a normalized record with a namespaced
    name + trust + requires_permission. Raises DiscoveryError on a bad name or a
    collision with an EXISTING (core/registered) tool."""
    name = str(tool.get("name", "")).strip()
    if not _TOOL_NAME_RE.match(name):
        raise DiscoveryError(f"invalid tool name '{name}' from server '{server}'")
    ns = namespaced(server, name)
    if ns in existing_names or name in existing_names:
        raise DiscoveryError(f"tool '{name}' from '{server}' shadows an existing tool")
    schema = tool.get("inputSchema")
    if schema is not None and not isinstance(schema, dict):
        raise DiscoveryError(f"tool '{name}' has a non-object inputSchema")
    return {
        "name": ns,
        "origin_name": name,
        "server": server,
        "description": str(tool.get("description", ""))[:500],
        "schema": schema or {"type": "object", "properties": {}},
    }


class MCPServerRegistry:
    """Operator-owned registry of declared external MCP servers + their tools."""

    def __init__(self, path: str = "data/mcp_servers.json"):
        self._path = Path(path)
        self._servers: Dict[str, Dict] = {}    # name -> {command, args, trust_class}
        self._tools: Dict[str, Dict] = {}       # namespaced name -> validated record
        self._load()

    def _load(self) -> None:
        if self._path.is_file():
            try:
                data = json.loads(self._path.read_text(encoding="utf-8"))
                for s in data.get("servers", []):
                    if s.get("name"):
                        self._servers[s["name"]] = {
                            "command": s.get("command", ""), "args": s.get("args", []),
                            "trust_class": s.get("trust_class", "unknown")}
            except (json.JSONDecodeError, OSError):
                pass

    def declare(self, name: str, command: str, args: Optional[List[str]] = None,
                trust_class: str = "unknown", persist: bool = False) -> Dict:
        if trust_class not in _SERVER_TRUST:
            raise DiscoveryError(f"unknown trust_class '{trust_class}' "
                                 f"(trusted|local|unknown)")
        self._servers[name] = {"command": command, "args": args or [],
                               "trust_class": trust_class}
        if persist:
            self._save()
        return {"server": name, "trust_class": trust_class}

    def servers(self) -> List[Dict]:
        return [{"name": n, **v} for n, v in sorted(self._servers.items())]

    def server_trust(self, server: str) -> str:
        tc = self._servers.get(server, {}).get("trust_class", "unknown")
        return _SERVER_TRUST.get(tc, ToolTrust.DISCOVERED_UNKNOWN)

    def discover(self, server: str, lister: ToolLister, core_names: Optional[set] = None) -> Dict:
        """Discover + validate + register a declared server's tools via `lister`.
        Unknown-server tools default to requires_permission + HIGH risk. Bad tools
        are skipped (reported), never registered."""
        if server not in self._servers:
            raise DiscoveryError(f"server '{server}' is not declared — declare() it first")
        existing = set(core_names or set()) | set(self._tools)
        trust = self.server_trust(server)
        registered, skipped = [], []
        for tool in lister(server):
            try:
                rec = validate_tool(tool, server, existing)
            except DiscoveryError as e:
                skipped.append({"tool": tool.get("name", "?"), "reason": str(e)})
                continue
            rec["trust"] = trust
            # Anything not from a trusted server is gated + treated as HIGH risk.
            rec["requires_permission"] = trust != ToolTrust.TRUSTED_SIGNED
            rec["risk"] = "high" if trust == ToolTrust.DISCOVERED_UNKNOWN else "medium"
            self._tools[rec["name"]] = rec
            existing.add(rec["name"])
            registered.append(rec["name"])
        return {"server": server, "trust": trust,
                "registered": registered, "skipped": skipped}

    def tools(self) -> List[Dict]:
        return [{"name": t["name"], "server": t["server"], "trust": t["trust"],
                 "risk": t["risk"], "requires_permission": t["requires_permission"]}
                for t in sorted(self._tools.values(), key=lambda x: x["name"])]

    def get_tool(self, namespaced_name: str) -> Optional[Dict]:
        return self._tools.get(namespaced_name)

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"servers": [{"name": n, **v} for n, v in self._servers.items()]}
        self._path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
