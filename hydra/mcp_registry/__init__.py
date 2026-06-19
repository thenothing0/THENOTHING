"""
Dynamic MCP Discovery (architecture spec Part 10).

Enterprise controls for discovering + registering tools from EXTERNAL MCP servers
without ceding safety:

  * **MCPServerRegistry** — operator-owned declared servers (data/mcp_servers.json),
    each with a trust class.
  * **Discovery** — lazily list a server's tools through an injectable lister
    (so it's testable without spawning), with a BOUNDED read that caps content
    BEFORE materialization (fixes PentesterFlow's M10 hostile-server OOM).
  * **Tool Security Validation** — schema-validate, reject duplicate/shadowing
    names, namespace as ``mcp:<server>:<tool>``.
  * **Trust scoring** — trusted-signed > declared-local > discovered-unknown;
    unknown tools default to requires-permission + HIGH risk.
  * **Isolation** — result size caps + per-call timeout policy.

Deterministic, stdlib-only, no real process spawning in this module.
"""

from .registry import (
    MAX_MCP_RESULT_BYTES,
    DiscoveryError,
    MCPServerRegistry,
    ToolTrust,
    bounded_result,
    namespaced,
    validate_tool,
)

__all__ = [
    "MCPServerRegistry",
    "ToolTrust",
    "validate_tool",
    "namespaced",
    "bounded_result",
    "DiscoveryError",
    "MAX_MCP_RESULT_BYTES",
]
