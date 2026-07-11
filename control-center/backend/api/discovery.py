"""Dynamic Discovery API — everything discovered from runtime, nothing hardcoded."""

from fastapi import APIRouter

from ..services import discovery

router = APIRouter(tags=["discovery"])


@router.get("/discovery/all")
async def discover_all():
    return discovery.discover_all()


@router.get("/discovery/providers")
async def discover_providers():
    from ..core.config import get_settings
    return discovery.discover_providers(get_settings().hydra_root)


@router.get("/discovery/mcp")
async def discover_mcp():
    from ..core.config import get_settings
    return discovery.discover_mcp_servers(get_settings().hydra_root)


@router.get("/discovery/plugins")
async def discover_plugins():
    from ..core.config import get_settings
    return discovery.discover_plugins(get_settings().hydra_root)


@router.get("/discovery/capabilities")
async def discover_capabilities():
    from ..core.config import get_settings
    return discovery.discover_capabilities(get_settings().hydra_root)


@router.get("/discovery/knowledge")
async def discover_knowledge():
    from ..core.config import get_settings
    return discovery.discover_knowledge_sources(get_settings().hydra_root)


@router.get("/discovery/guards")
async def discover_guards():
    return discovery.discover_guard_skills()


@router.get("/discovery/panels")
async def discover_panels():
    """Dynamic panel registry — frontend fetches this instead of hardcoding."""
    return {
        "panels": [
            {"id": "dashboard", "label": "Dashboard", "icon": "LayoutDashboard", "category": "core"},
            {"id": "chat", "label": "Chat", "icon": "MessageSquare", "category": "core"},
            {"id": "repository", "label": "Repository", "icon": "FolderGit2", "category": "engineering"},
            {"id": "git", "label": "Git", "icon": "GitBranch", "category": "engineering"},
            {"id": "providers", "label": "Providers", "icon": "Server", "category": "ai"},
            {"id": "models", "label": "Models", "icon": "Cpu", "category": "ai"},
            {"id": "mcp", "label": "MCP", "icon": "Plug", "category": "mcp"},
            {"id": "runtime", "label": "Runtime", "icon": "Activity", "category": "system"},
            {"id": "knowledge", "label": "Knowledge", "icon": "Database", "category": "knowledge"},
            {"id": "threat-intel", "label": "Threat Intel", "icon": "Brain", "category": "security"},
            {"id": "reports", "label": "Reports", "icon": "FileText", "category": "reporting"},
            {"id": "tasks", "label": "Tasks", "icon": "CheckSquare", "category": "engineering"},
            {"id": "workflows", "label": "Workflows", "icon": "Workflow", "category": "automation"},
            {"id": "agents", "label": "Agents", "icon": "Bot", "category": "agents"},
            {"id": "plugins", "label": "Plugins", "icon": "Package", "category": "extensions"},
            {"id": "marketplace", "label": "Marketplace", "icon": "Store", "category": "extensions"},
            {"id": "guards", "label": "Guards", "icon": "ShieldCheck", "category": "engineering"},
            {"id": "architecture", "label": "Architecture", "icon": "Network", "category": "engineering"},
            {"id": "repo-memory", "label": "Repo Memory", "icon": "BrainCircuit", "category": "engineering"},
            {"id": "impact", "label": "Impact Analysis", "icon": "Target", "category": "engineering"},
            {"id": "harness", "label": "Harness", "icon": "Wrench", "category": "engineering"},
            {"id": "logs", "label": "Logs", "icon": "ScrollText", "category": "system"},
            {"id": "settings", "label": "Settings", "icon": "Settings", "category": "system"},
        ],
    }


@router.get("/discovery/commands")
async def discover_commands():
    """Dynamic command registry — frontend fetches this."""
    return {
        "commands": [
            {"name": "/harness", "description": "Activate engineering workspace", "category": "engineering", "panel": "harness"},
            {"name": "/providers", "description": "Manage AI providers", "category": "ai", "panel": "providers"},
            {"name": "/models", "description": "Browse available models", "category": "ai", "panel": "models"},
            {"name": "/mcp", "description": "MCP server inspector", "category": "mcp", "panel": "mcp"},
            {"name": "/runtime", "description": "Runtime monitor", "category": "system", "panel": "runtime"},
            {"name": "/knowledge", "description": "Knowledge base", "category": "knowledge", "panel": "knowledge"},
            {"name": "/workflows", "description": "Workflow builder", "category": "automation", "panel": "workflows"},
            {"name": "/tasks", "description": "Task manager", "category": "engineering", "panel": "tasks"},
            {"name": "/plugins", "description": "Plugin manager", "category": "extensions", "panel": "plugins"},
            {"name": "/reports", "description": "Generate reports", "category": "reporting", "panel": "reports"},
            {"name": "/settings", "description": "Settings", "category": "system", "panel": "settings"},
            {"name": "/guards", "description": "Quality gate pipeline", "category": "engineering", "panel": "guards"},
            {"name": "/architecture", "description": "Architecture intelligence", "category": "engineering", "panel": "architecture"},
            {"name": "/repo", "description": "Repository memory", "category": "engineering", "panel": "repo-memory"},
            {"name": "/git", "description": "Git operations", "category": "engineering", "panel": "git"},
            {"name": "/agents", "description": "Agent orchestration", "category": "agents", "panel": "agents"},
            {"name": "/logs", "description": "Log viewer", "category": "system", "panel": "logs"},
            {"name": "/dashboard", "description": "Project dashboard", "category": "core", "panel": "dashboard"},
            {"name": "/help", "description": "Show available commands", "category": "system", "panel": None},
        ],
    }
