"""Search commands — hybrid knowledge search."""

from hydra.commands.registry import Command, CommandRegistry
from hydra.commands.result import CommandResult


def _search(args, kwargs, ctx):
    if not args:
        stats = ctx.services.search.get_stats()
        return CommandResult.success({"type": "search_stats", **stats})
    query = " ".join(args)
    mode = kwargs.get("mode", "hybrid")
    node_type = kwargs.get("type", "")
    limit = int(kwargs.get("limit", 20))
    target = kwargs.get("target", "")
    results = ctx.services.search.search(
        query, mode=mode, node_type=node_type, limit=limit, target=target,
    )
    return CommandResult.success({
        "type": "search_results",
        "query": query,
        "mode": mode,
        "count": len(results),
        "results": results,
    })


def _suggest(args, kwargs, ctx):
    if not args:
        return CommandResult.error("Usage: /suggest <partial>")
    partial = " ".join(args)
    limit = int(kwargs.get("limit", 10))
    suggestions = ctx.services.search.suggest(partial, limit=limit)
    return CommandResult.success({
        "type": "search_suggestions",
        "partial": partial,
        "suggestions": suggestions,
    })


def _facets(args, kwargs, ctx):
    query = " ".join(args) if args else ""
    facets = ctx.services.search.get_facets(query)
    return CommandResult.success({"type": "search_facets", **facets})


def register_search_commands(registry: CommandRegistry):
    registry.register(Command(
        name="hsearch", description="Hybrid knowledge search",
        category="intel", handler=_search,
        usage="/hsearch <query> [--mode hybrid|keyword|graph|semantic] [--type report|intel|...] [--limit N]",
    ))
    registry.register(Command(
        name="suggest", description="Auto-complete search suggestions",
        category="intel", handler=_suggest,
        usage="/suggest <partial>",
    ))
    registry.register(Command(
        name="facets", description="Search facets and counts",
        category="intel", handler=_facets,
        usage="/facets [query]",
    ))
