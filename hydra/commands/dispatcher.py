"""
Command Dispatcher — routes parsed commands to their handlers.

Single entry point: dispatcher.execute("/recon example.com") -> CommandResult.
"""

import logging
import uuid
from typing import Any

from hydra.commands.parser import parse_command
from hydra.commands.registry import CommandRegistry
from hydra.commands.result import CommandResult
from hydra.observability.logging import set_correlation_id
from hydra.observability.telemetry import telemetry
from hydra.observability.diagnostics import diagnostics

logger = logging.getLogger("hydra.commands.dispatcher")


class CommandContext:
    """Context passed to command handlers."""

    def __init__(self, services: Any, event_bus: Any, cmd_registry: Any = None):
        self.services = services
        self.event_bus = event_bus
        self._cmd_registry = cmd_registry


class CommandDispatcher:

    def __init__(self, registry: CommandRegistry, context: CommandContext):
        self._registry = registry
        self._context = context

    def set_chat_handler(self, handler: Any):
        """Set a handler for natural language (non-command) input."""
        self._chat_handler = handler

    def execute(self, raw_input: str) -> CommandResult:
        set_correlation_id(uuid.uuid4().hex[:12])

        parsed = parse_command(raw_input)
        if parsed is None:
            return CommandResult.error("Empty command")

        if parsed.name == "chat":
            handler = getattr(self, "_chat_handler", None)
            if handler:
                return handler(parsed.raw)
            return CommandResult.success({"type": "chat", "message": parsed.raw})

        command = self._registry.get(parsed.name)
        if command is None:
            suggestions = self._registry.complete(parsed.name)
            msg = f"Unknown command: /{parsed.name}"
            if suggestions:
                msg += f". Did you mean: /{', /'.join(suggestions[:3])}?"
            return CommandResult.error(msg)

        if command.handler is None:
            return CommandResult.error(f"/{parsed.name} has no handler")

        try:
            with telemetry.timer(f"cmd.{parsed.name}"):
                result = command.handler(parsed.args, parsed.kwargs, self._context)
            if not isinstance(result, CommandResult):
                result = CommandResult.success(result)
            return result
        except Exception as exc:
            diagnostics.capture(exc, {"command": parsed.name})
            logger.exception("command /%s failed", parsed.name)
            return CommandResult.error(f"/{parsed.name} failed: {exc}")

    def complete(self, partial: str) -> list[str]:
        return self._registry.complete(partial)
