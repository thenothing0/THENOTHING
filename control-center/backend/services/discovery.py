"""Dynamic Discovery — discover providers, models, MCP, plugins, guards from HYDRA runtime."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..core.config import get_settings


def discover_all(root: Path | None = None) -> dict[str, Any]:
    if root is None:
        root = get_settings().hydra_root

    return {
        "providers": discover_providers(root),
        "mcp_servers": discover_mcp_servers(root),
        "plugins": discover_plugins(root),
        "capabilities": discover_capabilities(root),
        "knowledge_sources": discover_knowledge_sources(root),
        "guard_skills": discover_guard_skills(),
    }


def discover_providers(root: Path) -> list[dict[str, Any]]:
    """Discover LLM provider configurations from hydra/llm/."""
    providers = []
    llm_dir = root / "hydra" / "llm"
    if llm_dir.is_dir():
        for py in llm_dir.glob("*.py"):
            if py.stem.startswith("_"):
                continue
            providers.append({
                "id": py.stem,
                "name": py.stem.replace("_", " ").title(),
                "source": "hydra.llm",
                "file": str(py.relative_to(root)),
            })

    ai_dir = root / "hydra" / "ai"
    if ai_dir.is_dir():
        providers.append({
            "id": "ai_router",
            "name": "AI Router",
            "source": "hydra.ai",
            "file": "hydra/ai/router.py",
        })

    return providers


def discover_mcp_servers(root: Path) -> list[dict[str, Any]]:
    servers = []
    for config_name in (".mcp.json", ".cursor/mcp.json"):
        config = root / config_name
        if config.exists():
            try:
                data = json.loads(config.read_text())
                mcp_servers = data.get("mcpServers", {})
                for name, srv in mcp_servers.items():
                    servers.append({
                        "name": name,
                        "command": srv.get("command", ""),
                        "args": srv.get("args", []),
                        "source": config_name,
                        "status": "configured",
                    })
            except Exception:
                pass
    return servers


def discover_plugins(root: Path) -> list[dict[str, Any]]:
    plugins = []
    plugin_dir = root / "hydra" / "plugins"
    if plugin_dir.is_dir():
        for item in plugin_dir.iterdir():
            if item.is_dir() and (item / "__init__.py").exists():
                plugins.append({
                    "id": item.name,
                    "name": item.name.replace("_", " ").title(),
                    "source": "hydra.plugins",
                    "path": str(item.relative_to(root)),
                })
            elif item.suffix == ".py" and not item.name.startswith("_"):
                plugins.append({
                    "id": item.stem,
                    "name": item.stem.replace("_", " ").title(),
                    "source": "hydra.plugins",
                    "path": str(item.relative_to(root)),
                })

    data_plugins = root / "data" / "plugins"
    if data_plugins.is_dir():
        for json_file in data_plugins.glob("*.json"):
            try:
                meta = json.loads(json_file.read_text())
                plugins.append({
                    "id": meta.get("id", json_file.stem),
                    "name": meta.get("name", json_file.stem),
                    "source": "data.plugins",
                    "path": str(json_file.relative_to(root)),
                    "version": meta.get("version", ""),
                })
            except Exception:
                pass

    return plugins


def discover_capabilities(root: Path) -> list[dict[str, Any]]:
    caps = []
    cap_dir = root / "hydra" / "capabilities"
    if cap_dir.is_dir():
        for py in cap_dir.glob("*.py"):
            if py.stem.startswith("_"):
                continue
            caps.append({"id": py.stem, "source": "hydra.capabilities", "file": str(py.relative_to(root))})

    data_caps = root / "data" / "capabilities.json"
    if data_caps.exists():
        try:
            data = json.loads(data_caps.read_text())
            if isinstance(data, list):
                for c in data:
                    caps.append({"id": c.get("id", ""), "source": "data", "category": c.get("category", "")})
            elif isinstance(data, dict):
                for cid, c in data.items():
                    caps.append({"id": cid, "source": "data", "category": c.get("category", "") if isinstance(c, dict) else ""})
        except Exception:
            pass

    return caps


def discover_knowledge_sources(root: Path) -> list[dict[str, Any]]:
    sources = []
    wiki = root / "wiki"
    if wiki.is_dir():
        for subdir in wiki.iterdir():
            if subdir.is_dir():
                md_count = len(list(subdir.glob("*.md")))
                if md_count > 0:
                    sources.append({
                        "id": subdir.name,
                        "name": subdir.name.replace("_", " ").replace("-", " ").title(),
                        "type": "wiki",
                        "count": md_count,
                    })

    data_dir = root / "data"
    if data_dir.is_dir():
        for db in data_dir.glob("*.db"):
            sources.append({
                "id": db.stem,
                "name": db.stem.replace("_", " ").title(),
                "type": "database",
                "path": str(db.relative_to(root)),
            })

    return sources


def discover_guard_skills() -> list[dict[str, str]]:
    from . import guard_pipeline
    return [
        {"id": g, "name": g.replace("_", " ").title(), "type": "guard"}
        for g in guard_pipeline.GUARD_ORDER
    ]
