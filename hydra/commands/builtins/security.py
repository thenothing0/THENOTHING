"""Security commands: /recon, /scan, /scope, /attack.

Command handlers return pending results for async operations.
The TUI spawns background workers; the CLI runs synchronously.
Events are emitted by the ScanService, not by the handlers.
"""

from hydra.commands.registry import Command, CommandRegistry
from hydra.commands.result import CommandResult


def _recon(args, kwargs, ctx):
    if not args:
        return CommandResult.error("Usage: /recon <target> [--depth=3]")
    target = args[0]
    depth = int(kwargs.get("depth", 3))
    return CommandResult.pending({
        "type": "recon", "target": target, "depth": depth,
    })


def _scan(args, kwargs, ctx):
    if len(args) < 2:
        return CommandResult.error("Usage: /scan <target> <vuln_class> [--context=any]")
    target, vuln_class = args[0], args[1]
    context = kwargs.get("context", "any")
    return CommandResult.pending({
        "type": "scan", "target": target, "vuln_class": vuln_class, "context": context,
    })


def _scope(args, kwargs, ctx):
    if not args:
        return CommandResult.error("Usage: /scope <program_url|register>")
    action = args[0]
    if action == "register":
        program = args[1] if len(args) > 1 else ""
        in_scope = kwargs.get("in_scope", "")
        platform = kwargs.get("platform", "custom")
        return CommandResult.success({
            "type": "scope_register", "program": program,
            "platform": platform, "in_scope": in_scope,
        })
    return CommandResult.success({"type": "scope_load", "url": action})


def _attack(args, kwargs, ctx):
    if not args:
        return CommandResult.error("Usage: /attack <target> [--classes=xss,sqli]")
    target = args[0]
    classes = kwargs.get("classes", "xss,sqli,open_redirect,lfi,ssti")
    return CommandResult.pending({
        "type": "attack_campaign", "target": target, "classes": classes,
    })


def register_security_commands(registry: CommandRegistry):
    registry.register(Command(
        name="recon", description="Start reconnaissance on a target",
        category="security", usage="/recon <target>", handler=_recon,
    ))
    registry.register(Command(
        name="scan", description="Run vulnerability scan",
        category="security", usage="/scan <target> <vuln_class>", handler=_scan,
    ))
    registry.register(Command(
        name="scope", description="Load or register bug bounty scope",
        category="security", usage="/scope <url|register>", handler=_scope,
    ))
    registry.register(Command(
        name="attack", description="Run attack campaign against target",
        category="security", usage="/attack <target> [--classes=xss,sqli]", handler=_attack,
    ))
