"""
Command System — shared across all HYDRA clients (TUI, CLI, MCP, automation).

Every client calls dispatcher.execute("/recon example.com") and gets back a
CommandResult. The TUI, CLI, and any future API all share this dispatch path.
"""

from hydra.commands.registry import CommandRegistry, Command
from hydra.commands.dispatcher import CommandDispatcher
from hydra.commands.result import CommandResult
from hydra.commands.parser import parse_command

__all__ = [
    "CommandRegistry", "Command", "CommandDispatcher",
    "CommandResult", "parse_command",
]
