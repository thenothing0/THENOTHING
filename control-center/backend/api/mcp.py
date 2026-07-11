import json
from pathlib import Path

from fastapi import APIRouter

from ..core.config import get_settings
from ..models.schemas import MCPServerInfo

router = APIRouter(prefix="/mcp", tags=["mcp"])


def _load_mcp_config() -> dict:
    cfg = get_settings().hydra_root / ".mcp.json"
    if cfg.exists():
        return json.loads(cfg.read_text())
    return {}


@router.get("/servers", response_model=list[MCPServerInfo])
async def list_servers():
    cfg = _load_mcp_config()
    servers = cfg.get("mcpServers", {})
    result = []
    for name, spec in servers.items():
        result.append(MCPServerInfo(
            name=name,
            command=spec.get("command", ""),
            args=spec.get("args", []),
            status="configured",
            env=spec.get("env", {}),
        ))
    return result


@router.get("/tools/count")
async def tool_count():
    from ..services.repo_analyzer import count_mcp_tools
    return {"count": count_mcp_tools()}


@router.get("/config")
async def mcp_config():
    return _load_mcp_config()


@router.get("/inspector")
async def mcp_inspector():
    """Expanded MCP inspector data for Phase 2 panel."""
    cfg = _load_mcp_config()
    servers = cfg.get("mcpServers", {})
    from ..services.repo_analyzer import count_mcp_tools

    tool_total = count_mcp_tools()
    server_list = []
    for name, spec in servers.items():
        server_list.append({
            "name": name,
            "command": spec.get("command", ""),
            "args": spec.get("args", []),
            "env_vars": list(spec.get("env", {}).keys()),
            "cwd": spec.get("cwd", ""),
            "status": "configured",
        })

    # Parse tool categories from mcp_server.py
    categories: dict[str, int] = {}
    mcp_file = get_settings().hydra_root / "mcp_server.py"
    if mcp_file.exists():
        try:
            content = mcp_file.read_text(errors="replace")
            import re
            for match in re.finditer(r'(?:async\s+)?def\s+(\w+)\s*\(', content):
                fn_name = match.group(1)
                if fn_name.startswith("_"):
                    continue
                prefix = fn_name.split("_")[0]
                categories[prefix] = categories.get(prefix, 0) + 1
        except Exception:
            pass

    return {
        "servers": server_list,
        "server_count": len(server_list),
        "tool_count": tool_total,
        "tool_categories": dict(sorted(categories.items(), key=lambda x: -x[1])[:20]),
        "health": "healthy" if server_list else "no_servers",
    }
