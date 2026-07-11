"""Graph, TTP, and Memory commands."""

from hydra.commands.registry import Command, CommandRegistry
from hydra.commands.result import CommandResult


def _graph(args, kwargs, ctx):
    if not args:
        stats = ctx.services.graph.get_stats()
        return CommandResult.success({"type": "graph_stats", **stats})
    subcmd = args[0]
    if subcmd == "neighbors" and len(args) > 1:
        slug = args[1]
        node_type = kwargs.get("type", "")
        results = ctx.services.graph.neighbors(slug, node_type=node_type)
        return CommandResult.success({"type": "graph_neighbors", "slug": slug, "neighbors": results})
    if subcmd == "path" and len(args) > 2:
        path = ctx.services.graph.shortest_path(args[1], args[2])
        return CommandResult.success({"type": "graph_path", "path": path})
    if subcmd == "subgraph" and len(args) > 1:
        depth = int(kwargs.get("depth", 2))
        sg = ctx.services.graph.subgraph(args[1], depth=depth)
        return CommandResult.success({"type": "graph_subgraph", **sg})
    if subcmd == "entities" and len(args) > 1:
        limit = int(kwargs.get("limit", 50))
        entities = ctx.services.graph.entities_by_type(args[1], limit=limit)
        return CommandResult.success({"type": "graph_entities", "node_type": args[1], "entities": entities})
    return CommandResult.error(
        "Usage: /graph [neighbors <slug>|path <a> <b>|subgraph <slug>|entities <type>]"
    )


def _ttp(args, kwargs, ctx):
    if not args:
        stats = ctx.services.ttp.get_stats()
        return CommandResult.success({"type": "ttp_stats", **stats})
    subcmd = args[0]
    if subcmd == "extract" and len(args) > 1:
        text = " ".join(args[1:])
        result = ctx.services.ttp.extract_ttps(text)
        return CommandResult.success({"type": "ttp_extraction", **result})
    if subcmd == "coverage":
        limit = int(kwargs.get("limit", 20))
        coverage = ctx.services.ttp.get_coverage(limit=limit)
        return CommandResult.success({"type": "ttp_coverage", "coverage": coverage})
    if subcmd == "technique" and len(args) > 1:
        info = ctx.services.ttp.get_technique_info(args[1])
        return CommandResult.success({"type": "ttp_technique", **info})
    if subcmd == "playbook":
        return CommandResult.error("Usage: /ttp playbook — requires findings via API")
    return CommandResult.error(
        "Usage: /ttp [extract <text>|coverage|technique <id>|playbook]"
    )


def _memory(args, kwargs, ctx):
    if not args:
        stats = ctx.services.memory.get_stats()
        return CommandResult.success({"type": "memory_stats", **stats})
    subcmd = args[0]
    if subcmd == "recall" and len(args) > 1:
        query = " ".join(args[1:])
        target = kwargs.get("target", "")
        limit = int(kwargs.get("limit", 10))
        results = ctx.services.memory.recall(query, target=target, limit=limit)
        return CommandResult.success({"type": "memory_recall", "query": query, "results": results})
    if subcmd == "recent":
        limit = int(kwargs.get("limit", 20))
        kind = kwargs.get("kind", "")
        entries = ctx.services.memory.get_recent(limit=limit, kind=kind)
        return CommandResult.success({"type": "memory_recent", "entries": entries})
    if subcmd == "record" and len(args) > 2:
        kind = args[1]
        content = " ".join(args[2:])
        target = kwargs.get("target", "")
        result = ctx.services.memory.record(kind, content, target=target)
        return CommandResult.success({"type": "memory_recorded", **result})
    return CommandResult.error(
        "Usage: /memory [recall <query>|recent|record <kind> <content>]"
    )


def register_graph_commands(registry: CommandRegistry):
    registry.register(Command(
        name="graph", description="Knowledge graph queries",
        category="intel", handler=_graph,
        usage="/graph [neighbors <slug>|path <a> <b>|subgraph <slug>|entities <type>]",
    ))
    registry.register(Command(
        name="ttp", description="MITRE ATT&CK TTP analysis",
        category="intel", handler=_ttp,
        usage="/ttp [extract <text>|coverage|technique <id>|playbook]",
    ))
    registry.register(Command(
        name="memory", description="Cyber memory recall and recording",
        category="intel", handler=_memory,
        usage="/memory [recall <query>|recent|record <kind> <content>]",
    ))
