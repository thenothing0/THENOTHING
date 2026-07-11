"""Findings commands: /finding, /validate, /confirm, /reject, /report."""

from hydra.commands.registry import Command, CommandRegistry
from hydra.commands.result import CommandResult


def _finding(args, kwargs, ctx):
    if not args:
        return CommandResult.error("Usage: /finding <finding_id>")
    fid = args[0]
    detail = ctx.services.findings.get_finding(fid)
    if detail is None:
        return CommandResult.error(f"Finding not found: {fid}")
    return CommandResult.success({"type": "finding_detail", "finding": detail})


def _validate(args, kwargs, ctx):
    if not args:
        return CommandResult.error("Usage: /validate <finding_id>")
    result = ctx.services.findings.transition(args[0], "validated")
    return CommandResult.success({"type": "finding_transitioned", **result})


def _confirm(args, kwargs, ctx):
    if not args:
        return CommandResult.error("Usage: /confirm <finding_id>")
    result = ctx.services.findings.transition(args[0], "confirmed")
    return CommandResult.success({"type": "finding_transitioned", **result})


def _reject(args, kwargs, ctx):
    if not args:
        return CommandResult.error("Usage: /reject <finding_id>")
    result = ctx.services.findings.transition(args[0], "rejected")
    return CommandResult.success({"type": "finding_transitioned", **result})


def register_findings_commands(registry: CommandRegistry):
    registry.register(Command(
        name="finding", description="View finding detail",
        category="findings", usage="/finding <id>", handler=_finding,
    ))
    registry.register(Command(
        name="validate", description="Transition finding to validated",
        category="findings", usage="/validate <id>", handler=_validate,
    ))
    registry.register(Command(
        name="confirm", description="Transition finding to confirmed (evidence-gated)",
        category="findings", usage="/confirm <id>", handler=_confirm,
    ))
    registry.register(Command(
        name="reject", description="Reject a finding",
        category="findings", usage="/reject <id>", handler=_reject,
    ))
