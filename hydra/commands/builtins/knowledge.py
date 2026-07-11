"""Knowledge commands: /search, /recall, /learn."""

from hydra.commands.registry import Command, CommandRegistry
from hydra.commands.result import CommandResult


def _search(args, kwargs, ctx):
    if not args:
        return CommandResult.error("Usage: /search <query>")
    query = " ".join(args)
    results = ctx.services.knowledge.search(query)
    return CommandResult.success({"type": "search_results", "query": query, "results": results})


def _recall(args, kwargs, ctx):
    if not args:
        return CommandResult.error("Usage: /recall <query>")
    query = " ".join(args)
    results = ctx.services.knowledge.recall(query)
    return CommandResult.success({"type": "recall_results", "query": query, "results": results})


def _learn(args, kwargs, ctx):
    if not args:
        return CommandResult.error("Usage: /learn <lesson text>")
    lesson = " ".join(args)
    tier = kwargs.get("tier", "project")
    category = kwargs.get("category", "manual")
    result = ctx.services.learning.record(tier=tier, title=lesson[:60], category=category, lesson=lesson)
    return CommandResult.success({"type": "learn_recorded", **result})


def _wiki(args, kwargs, ctx):
    if not args:
        return CommandResult.error("Usage: /wiki <page_slug>")
    slug = args[0]
    page = ctx.services.knowledge.get_page(slug)
    if page is None:
        return CommandResult.error(f"Page not found: {slug}")
    return CommandResult.success({"type": "wiki_page", "page": page, "slug": slug})


def _next(args, kwargs, ctx):
    eid = getattr(ctx, "engagement_id", None)
    limit = int(kwargs.get("limit", 10))
    if eid:
        targets = ctx.services.coverage.next_targets(eid, limit=limit)
        return CommandResult.success({"type": "coverage_next", "targets": targets})
    return CommandResult.success({"type": "coverage_next", "targets": []})


def _lint(args, kwargs, ctx):
    result = ctx.services.knowledge.lint()
    return CommandResult.success({"type": "kb_lint", "result": result})


def register_knowledge_commands(registry: CommandRegistry):
    registry.register(Command(
        name="search", description="Search knowledge base",
        category="knowledge", usage="/search <query>", handler=_search,
    ))
    registry.register(Command(
        name="recall", description="Offensive memory recall",
        category="knowledge", usage="/recall <query>", handler=_recall,
    ))
    registry.register(Command(
        name="learn", description="Record a lesson",
        category="knowledge", usage="/learn <lesson> [--tier=project] [--category=manual]",
        handler=_learn,
    ))
    registry.register(Command(
        name="wiki", description="View a knowledge base page",
        category="knowledge", usage="/wiki <page_slug>", handler=_wiki,
    ))
    registry.register(Command(
        name="next", description="Suggest next untested targets",
        category="knowledge", usage="/next [--limit=10]", handler=_next,
    ))
    registry.register(Command(
        name="lint", description="Check knowledge base health",
        category="knowledge", usage="/lint", handler=_lint,
    ))
