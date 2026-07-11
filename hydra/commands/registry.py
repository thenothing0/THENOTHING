"""
Command Registry — all commands register here at import time.

Commands are discovered from builtins/, plugins/, and the CapabilityRegistry.
Any client (TUI, CLI, MCP, automation) queries this registry to find and
execute commands.
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Callable

logger = logging.getLogger("hydra.commands.registry")


@dataclass
class Command:
    name: str
    description: str
    category: str = "system"
    usage: str = ""
    handler: Callable | None = None
    hidden: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


class CommandRegistry:
    """Thread-safe registry of all HYDRA commands."""

    def __init__(self):
        self._commands: dict[str, Command] = {}

    def register(self, command: Command) -> None:
        self._commands[command.name] = command
        logger.debug("command registered: /%s", command.name)

    def unregister(self, name: str) -> None:
        self._commands.pop(name, None)

    def get(self, name: str) -> Command | None:
        return self._commands.get(name)

    def list_commands(self, category: str | None = None,
                      include_hidden: bool = False) -> list[Command]:
        cmds = list(self._commands.values())
        if not include_hidden:
            cmds = [c for c in cmds if not c.hidden]
        if category:
            cmds = [c for c in cmds if c.category == category]
        return sorted(cmds, key=lambda c: (c.category, c.name))

    def complete(self, partial: str) -> list[str]:
        partial = partial.lstrip("/")
        return sorted(
            name for name in self._commands
            if name.startswith(partial) and not self._commands[name].hidden
        )

    def categories(self) -> list[str]:
        return sorted({c.category for c in self._commands.values()})
