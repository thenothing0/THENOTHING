"""Agent, Workflow, and Router commands."""

from hydra.commands.registry import Command, CommandRegistry
from hydra.commands.result import CommandResult


def _agents(args, kwargs, ctx):
    if not args:
        stats = ctx.services.agents.get_stats()
        return CommandResult.success({"type": "agent_stats", **stats})
    subcmd = args[0]
    if subcmd == "list":
        agents = ctx.services.agents.list_agents()
        return CommandResult.success({"type": "agent_list", "agents": agents})
    if subcmd == "detect" and len(args) > 1:
        result = ctx.services.agents.detect_target_type(args[1])
        return CommandResult.success({"type": "agent_detect", **result})
    if subcmd == "spawn" and len(args) > 1:
        agent_type = args[1]
        task_id = kwargs.get("task", "")
        result = ctx.services.agents.spawn_agent(agent_type, {"id": task_id})
        return CommandResult.success({"type": "agent_spawn", **result})
    if subcmd == "status":
        status = ctx.services.agents.get_coordinator_status()
        return CommandResult.success({"type": "agent_coordinator", **status})
    return CommandResult.error(
        "Usage: /agents [list|detect <target>|spawn <type>|status]"
    )


def _workflow(args, kwargs, ctx):
    if not args:
        stats = ctx.services.workflows.get_stats()
        return CommandResult.success({"type": "workflow_stats", **stats})
    subcmd = args[0]
    if subcmd == "templates":
        templates = ctx.services.workflows.list_templates()
        return CommandResult.success({"type": "workflow_templates", "templates": templates})
    if subcmd == "create" and len(args) > 1:
        target = args[1]
        template = kwargs.get("template", "full_bounty")
        result = ctx.services.workflows.create_workflow(target, template=template)
        return CommandResult.success({"type": "workflow_created", **result})
    if subcmd == "status" and len(args) > 1:
        status = ctx.services.workflows.get_status(args[1])
        return CommandResult.success({"type": "workflow_status", **status})
    if subcmd == "advance" and len(args) > 2:
        result = ctx.services.workflows.advance(args[1], args[2])
        return CommandResult.success({"type": "workflow_advanced", **result})
    if subcmd == "runs":
        runs = ctx.services.workflows.list_runs()
        return CommandResult.success({"type": "workflow_runs", "runs": runs})
    return CommandResult.error(
        "Usage: /workflow [templates|create <target>|status <id>|advance <id> <state>|runs]"
    )


def _router(args, kwargs, ctx):
    if not args:
        stats = ctx.services.router.get_stats()
        return CommandResult.success({"type": "router_stats", **stats})
    subcmd = args[0]
    if subcmd == "providers":
        providers = ctx.services.router.list_providers()
        return CommandResult.success({"type": "router_providers", "providers": providers})
    if subcmd == "tasks":
        tasks = ctx.services.router.list_task_types()
        return CommandResult.success({"type": "router_tasks", "tasks": tasks})
    if subcmd == "tiers":
        tiers = ctx.services.router.list_model_tiers()
        return CommandResult.success({"type": "router_tiers", "tiers": tiers})
    if subcmd == "select" and len(args) > 1:
        result = ctx.services.router.select_model(task_type=args[1])
        return CommandResult.success({"type": "router_select", **result})
    if subcmd == "health":
        health = ctx.services.router.get_provider_health()
        return CommandResult.success({"type": "router_health", **health})
    return CommandResult.error(
        "Usage: /router [providers|tasks|tiers|select <task_type>|health]"
    )


def register_agent_commands(registry: CommandRegistry):
    registry.register(Command(
        name="agents", description="Agent ecosystem management",
        category="intel", handler=_agents,
        usage="/agents [list|detect <target>|spawn <type>|status]",
    ))
    registry.register(Command(
        name="workflows", description="Autonomous workflow orchestration",
        category="intel", handler=_workflow,
        usage="/workflows [templates|create <target>|status <id>|advance <id> <state>|runs]",
    ))
    registry.register(Command(
        name="router", description="Multi-model AI router management",
        category="intel", handler=_router,
        usage="/router [providers|tasks|tiers|select <task_type>|health]",
    ))
