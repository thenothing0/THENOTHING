from fastapi import APIRouter

from ..models.schemas import CommandEntry

router = APIRouter(prefix="/commands", tags=["commands"])

_COMMANDS: list[CommandEntry] = [
    CommandEntry(name="/harness", description="Engineering workspace — auto-detects context", category="engineering"),
    CommandEntry(name="/providers", description="Manage AI providers", category="ai"),
    CommandEntry(name="/models", description="Browse and switch models", category="ai"),
    CommandEntry(name="/mcp", description="MCP server management", category="mcp"),
    CommandEntry(name="/knowledge", description="Knowledge base browser", category="knowledge"),
    CommandEntry(name="/recon", description="Reconnaissance workspace", category="security"),
    CommandEntry(name="/report", description="Generate reports", category="reporting"),
    CommandEntry(name="/workflow", description="Workflow builder", category="automation"),
    CommandEntry(name="/agents", description="Agent orchestration", category="agents"),
    CommandEntry(name="/runtime", description="Runtime monitor", category="system"),
    CommandEntry(name="/logs", description="Log viewer", category="system"),
    CommandEntry(name="/tasks", description="Task manager", category="engineering"),
    CommandEntry(name="/plugins", description="Plugin marketplace", category="extensions"),
    CommandEntry(name="/settings", description="Platform settings", category="system"),
    CommandEntry(name="/search", description="Search codebase", category="engineering", shortcut="Ctrl+Shift+F"),
    CommandEntry(name="/git", description="Git operations", category="engineering"),
    CommandEntry(name="/help", description="Show all commands", category="system", shortcut="Ctrl+Shift+P"),
]


@router.get("", response_model=list[CommandEntry])
async def list_commands(category: str | None = None):
    if category:
        return [c for c in _COMMANDS if c.category == category]
    return _COMMANDS


@router.get("/search")
async def search_commands(q: str):
    q_lower = q.lower()
    return [c for c in _COMMANDS if q_lower in c.name.lower() or q_lower in c.description.lower()]
