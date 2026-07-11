"""Navigation commands: /findings, /coverage, /knowledge, /workflow, /engage."""

from hydra.commands.registry import Command, CommandRegistry
from hydra.commands.result import CommandResult


def _findings(args, kwargs, ctx):
    eid = getattr(ctx, "engagement_id", None)
    state = kwargs.get("state", "")
    if eid:
        findings = ctx.services.findings.list_findings(eid, state)
        return CommandResult.success({"type": "findings_list", "findings": findings})
    return CommandResult.success({"type": "findings_list", "findings": []})


def _coverage(args, kwargs, ctx):
    eid = getattr(ctx, "engagement_id", None)
    if eid:
        summary = ctx.services.coverage.get_summary(eid)
        return CommandResult.success({"type": "coverage", "summary": summary})
    return CommandResult.success({"type": "coverage", "summary": {}})


def _knowledge(args, kwargs, ctx):
    return CommandResult.success({"type": "knowledge_home"})


def _workflow(args, kwargs, ctx):
    action = args[0] if args else "status"
    wid = getattr(ctx, "workflow_id", None)
    if action == "status" and wid:
        info = ctx.services.engagement.get_workflow(wid)
        return CommandResult.success({"type": "workflow_status", "workflow": info})
    return CommandResult.success({"type": "workflow_status", "workflow": None})


def _engage(args, kwargs, ctx):
    if args:
        eid = args[0]
        return CommandResult.success({"type": "engage_switch", "engagement_id": eid})
    engagements = ctx.services.engagement.list_engagements()
    return CommandResult.success({"type": "engage_list", "engagements": engagements})


def register_navigation_commands(registry: CommandRegistry):
    registry.register(Command(
        name="findings", description="List findings for current engagement",
        category="navigation", usage="/findings [--state=<state>]", handler=_findings,
    ))
    registry.register(Command(
        name="coverage", description="Show coverage for current engagement",
        category="navigation", usage="/coverage", handler=_coverage,
    ))
    registry.register(Command(
        name="knowledge", description="Browse knowledge base",
        category="navigation", usage="/knowledge", handler=_knowledge,
    ))
    registry.register(Command(
        name="workflow", description="Show pentest workflow status",
        category="navigation", usage="/workflow [status]", handler=_workflow,
    ))
    registry.register(Command(
        name="engage", description="List or switch engagements",
        category="navigation", usage="/engage [engagement_id]", handler=_engage,
    ))
