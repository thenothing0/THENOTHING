"""Collaboration, Skill Evolution, Knowledge Builder commands (Phase 10 Batch 3)."""

from hydra.commands.registry import Command, CommandRegistry
from hydra.commands.result import CommandResult


def _collab(args, kwargs, ctx):
    if not args:
        stats = ctx.services.collaboration.get_stats()
        return CommandResult.success({"type": "collab_stats", **stats})
    subcmd = args[0]
    if subcmd == "create":
        desc = " ".join(args[1:]) or "Unnamed task"
        role = kwargs.get("role", "scanner")
        target = kwargs.get("target", "")
        result = ctx.services.collaboration.create_task(desc, role=role, target=target)
        return CommandResult.success({"type": "collab_task_created", **result})
    if subcmd == "tasks":
        state = kwargs.get("state", "")
        tasks = ctx.services.collaboration.list_tasks(state=state)
        return CommandResult.success({"type": "collab_tasks", "tasks": tasks})
    if subcmd == "share":
        finding = {"description": " ".join(args[1:])}
        result = ctx.services.collaboration.share_finding(finding)
        return CommandResult.success({"type": "collab_shared", **result})
    if subcmd == "findings":
        findings = ctx.services.collaboration.get_shared_findings()
        return CommandResult.success({"type": "collab_findings", "findings": findings})
    return CommandResult.error(
        "Usage: /collab [create <desc>|tasks|share <finding>|findings]"
    )


def _evolve(args, kwargs, ctx):
    if not args:
        stats = ctx.services.skill_evolution.get_stats()
        return CommandResult.success({"type": "evolve_stats", **stats})
    subcmd = args[0]
    if subcmd == "register" and len(args) > 1:
        name = " ".join(args[1:])
        category = kwargs.get("category", "scanning")
        result = ctx.services.skill_evolution.register_skill(name, category=category)
        return CommandResult.success({"type": "evolve_registered", **result})
    if subcmd == "rank":
        category = kwargs.get("category", "")
        ranked = ctx.services.skill_evolution.rank_skills(category=category)
        return CommandResult.success({"type": "evolve_ranked", "skills": ranked})
    if subcmd == "deprecated":
        deps = ctx.services.skill_evolution.get_deprecated()
        return CommandResult.success({"type": "evolve_deprecated", "skills": deps})
    return CommandResult.error(
        "Usage: /evolve [register <name>|rank|deprecated]"
    )


def _kbuild(args, kwargs, ctx):
    if not args:
        stats = ctx.services.knowledge_builder.get_stats()
        return CommandResult.success({"type": "kbuild_stats", **stats})
    subcmd = args[0]
    if subcmd == "gaps":
        result = ctx.services.knowledge_builder.find_gaps()
        return CommandResult.success({"type": "kbuild_gaps", **result})
    if subcmd == "node" and len(args) > 2:
        node_id = args[1]
        node_type = args[2]
        result = ctx.services.knowledge_builder.add_node(node_id, node_type)
        return CommandResult.success({**result, "type": "kbuild_node_added"})
    if subcmd == "subgraph" and len(args) > 1:
        depth = int(kwargs.get("depth", 1))
        result = ctx.services.knowledge_builder.get_subgraph(args[1], depth=depth)
        return CommandResult.success({"type": "kbuild_subgraph", **result})
    return CommandResult.error(
        "Usage: /kbuild [gaps|node <id> <type>|subgraph <id>]"
    )


def register_collab_commands(registry: CommandRegistry):
    registry.register(Command(
        name="collab", description="Multi-agent collaboration",
        category="intel", handler=_collab,
        usage="/collab [create|tasks|share|findings]",
    ))
    registry.register(Command(
        name="evolve", description="Self-evolving skill management",
        category="intel", handler=_evolve,
        usage="/evolve [register <name>|rank|deprecated]",
    ))
    registry.register(Command(
        name="kbuild", description="Knowledge graph builder",
        category="intel", handler=_kbuild,
        usage="/kbuild [gaps|node <id> <type>|subgraph <id>]",
    ))
