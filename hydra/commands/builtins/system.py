"""System commands: /help, /status, /clear, /session, /tools."""

from hydra.commands.registry import Command, CommandRegistry
from hydra.commands.result import CommandResult


def _help(args, kwargs, ctx):
    registry = getattr(ctx, "_cmd_registry", None)
    commands = []
    if registry:
        cmds = registry.list_commands()
        commands = [
            {"name": c.name, "description": c.description,
             "category": c.category, "usage": c.usage}
            for c in cmds
        ]
    return CommandResult.success({"type": "help", "commands": commands})


def _status(args, kwargs, ctx):
    health = ctx.services.system.get_health()
    return CommandResult.success({"type": "status", **health})


def _clear(args, kwargs, ctx):
    return CommandResult.success({"type": "clear"})


def _tools(args, kwargs, ctx):
    tools = ctx.services.system.check_tools()
    return CommandResult.success({"type": "tools", "tools": tools})


def _session(args, kwargs, ctx):
    action = args[0] if args else "list"
    if action == "save":
        return CommandResult.success({"type": "session_save"})
    elif action == "list":
        return CommandResult.success({"type": "session_list"})
    elif action == "load":
        sid = args[1] if len(args) > 1 else None
        return CommandResult.success({"type": "session_load", "session_id": sid})
    return CommandResult.error(f"Unknown session action: {action}")


def register_system_commands(registry: CommandRegistry):
    registry.register(Command(
        name="help", description="List all available commands",
        category="system", usage="/help", handler=_help,
    ))
    registry.register(Command(
        name="status", description="Show system health and status",
        category="system", usage="/status", handler=_status,
    ))
    registry.register(Command(
        name="clear", description="Clear conversation output",
        category="system", usage="/clear", handler=_clear,
    ))
    registry.register(Command(
        name="tools", description="Check available security tools",
        category="system", usage="/tools", handler=_tools,
    ))
    registry.register(Command(
        name="session", description="Session management (save/load/list)",
        category="system", usage="/session <save|load|list>", handler=_session,
    ))
