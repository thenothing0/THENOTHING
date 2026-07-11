"""Learning Loop, Confidence, and Quality commands (Phase 10)."""

from hydra.commands.registry import Command, CommandRegistry
from hydra.commands.result import CommandResult


def _learn(args, kwargs, ctx):
    if not args:
        stats = ctx.services.learning_loop.get_stats()
        return CommandResult.success({"type": "learning_stats", **stats})
    subcmd = args[0]
    if subcmd == "process" and len(args) > 1:
        activity_type = args[1]
        target = kwargs.get("target", "")
        result = ctx.services.learning_loop.process_activity(activity_type, target=target)
        return CommandResult.success({"type": "learning_processed", **result})
    if subcmd == "recent":
        limit = int(kwargs.get("limit", 20))
        events = ctx.services.learning_loop.get_recent(limit=limit)
        return CommandResult.success({"type": "learning_recent", "events": events})
    if subcmd == "queue":
        queue = ctx.services.learning_loop.get_improvement_queue()
        return CommandResult.success({"type": "learning_queue", "improvements": queue})
    return CommandResult.error(
        "Usage: /learning [process <type> --target T|recent|queue]"
    )


def _confidence(args, kwargs, ctx):
    if not args:
        stats = ctx.services.confidence.get_stats()
        return CommandResult.success({"type": "confidence_stats", **stats})
    subcmd = args[0]
    if subcmd == "score" and len(args) > 1:
        slug = args[1]
        sources = int(kwargs.get("sources", 1))
        confirms = int(kwargs.get("confirms", 0))
        result = ctx.services.confidence.score(slug, source_count=sources, confirmations=confirms)
        return CommandResult.success({"type": "confidence_score", **result})
    if subcmd == "bands":
        bands = ctx.services.confidence.list_bands()
        return CommandResult.success({"type": "confidence_bands", "bands": bands})
    if subcmd == "decay" and len(args) > 1:
        import time
        days = float(args[1])
        ts = time.time() - (days * 86400)
        result = ctx.services.confidence.decay_check(ts)
        return CommandResult.success({"type": "confidence_decay", **result})
    return CommandResult.error(
        "Usage: /confidence [score <slug> --sources N --confirms N|bands|decay <days>]"
    )


def _quality(args, kwargs, ctx):
    if not args:
        stats = ctx.services.quality.get_stats()
        return CommandResult.success({"type": "quality_stats", **stats})
    subcmd = args[0]
    if subcmd == "audit":
        scope = kwargs.get("scope", "all")
        limit = int(kwargs.get("limit", 50))
        result = ctx.services.quality.audit(scope=scope, limit=limit)
        return CommandResult.success({"type": "quality_audit", **result})
    if subcmd == "check" and len(args) > 1:
        result = ctx.services.quality.check_page(args[1])
        return CommandResult.success({"type": "quality_check", **result})
    if subcmd == "health":
        result = ctx.services.quality.get_health_score()
        return CommandResult.success({"type": "quality_health", **result})
    return CommandResult.error(
        "Usage: /quality [audit --scope all|check <slug>|health]"
    )


def register_learning_commands(registry: CommandRegistry):
    registry.register(Command(
        name="learning", description="Continuous learning loop",
        category="intel", handler=_learn,
        usage="/learning [process <type>|recent|queue]",
    ))
    registry.register(Command(
        name="confidence", description="Knowledge confidence scoring",
        category="intel", handler=_confidence,
        usage="/confidence [score <slug>|bands|decay <days>]",
    ))
    registry.register(Command(
        name="quality", description="Knowledge quality control",
        category="intel", handler=_quality,
        usage="/quality [audit|check <slug>|health]",
    ))
