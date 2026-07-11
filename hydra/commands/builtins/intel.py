"""Intel commands: /ingest, /reports, /extract, /intel-stats."""

from hydra.commands.registry import Command, CommandRegistry
from hydra.commands.result import CommandResult


def _ingest(args, kwargs, ctx):
    if not args:
        return CommandResult.error(
            "Usage: /ingest <path_or_text> [--title=...] [--target=...] "
            "[--source-type=writeup] [--source-url=...]"
        )
    text = " ".join(args)
    title = kwargs.get("title", "")
    target = kwargs.get("target", "")
    source_type = kwargs.get("source-type", kwargs.get("source_type", "writeup"))
    source_url = kwargs.get("source-url", kwargs.get("source_url", ""))

    from pathlib import Path
    p = Path(text)
    if p.is_file():
        result = ctx.services.ingest.ingest_file(
            str(p), title=title, target=target,
            source_url=source_url, source_type=source_type,
        )
    else:
        result = ctx.services.ingest.ingest_text(
            text, title=title, target=target,
            source_url=source_url, source_type=source_type,
        )

    if result.ok:
        return CommandResult.success({
            "type": "ingest_result",
            "slug": result.slug,
            "title": result.title,
            "learning_score": result.learning_score,
            "vuln_class": result.vuln_class,
        })
    return CommandResult.error(f"Ingestion failed: {result.error}")


def _reports(args, kwargs, ctx):
    target = kwargs.get("target", "")
    vuln_class = kwargs.get("vuln-class", kwargs.get("vuln_class", ""))
    min_score = int(kwargs.get("min-score", kwargs.get("min_score", 0)))
    limit = int(kwargs.get("limit", 20))

    if args and args[0] == "stats":
        stats = ctx.services.report_store.get_stats()
        return CommandResult.success({"type": "report_stats", **stats})

    if args and args[0] == "by-vuln":
        agg = ctx.services.report_store.aggregate_by_vuln_class()
        return CommandResult.success({"type": "report_aggregation", "by": "vuln_class", "data": agg})

    if args and args[0] == "by-target":
        agg = ctx.services.report_store.aggregate_by_target()
        return CommandResult.success({"type": "report_aggregation", "by": "target", "data": agg})

    if args and args[0] == "high-value":
        reports = ctx.services.report_store.get_high_value(
            min_score=min_score or 7, limit=limit,
        )
        return CommandResult.success({"type": "report_list", "reports": reports})

    reports = ctx.services.report_store.list_reports(
        target=target, vuln_class=vuln_class,
        min_score=min_score, limit=limit,
    )
    return CommandResult.success({"type": "report_list", "reports": reports})


def _extract(args, kwargs, ctx):
    if not args:
        field_types = ctx.services.extraction.list_field_types()
        return CommandResult.success({
            "type": "extraction_fields",
            "available": field_types,
            "usage": "/extract <field_type> <text_or_slug>",
        })
    field_type = args[0]
    text = " ".join(args[1:]) if len(args) > 1 else ""
    model = kwargs.get("model", "")

    if not text:
        return CommandResult.error(f"Usage: /extract {field_type} <text_or_wiki_slug>")

    page = ctx.services.knowledge.get_page(text)
    if page is not None:
        body = page.body if hasattr(page, "body") else str(page)
        text = body

    result = ctx.services.extraction.extract_field(text, field_type, model=model)
    if result.ok:
        return CommandResult.success({
            "type": "extraction_result",
            "field_type": field_type,
            "fields": result.fields,
            "confidence": result.confidence,
        })
    return CommandResult.error(f"Extraction failed: {result.error}")


def _intel_stats(args, kwargs, ctx):
    stats = ctx.services.ingest.get_stats()
    return CommandResult.success({"type": "intel_stats", **stats})


def register_intel_commands(registry: CommandRegistry):
    registry.register(Command(
        name="ingest", description="Ingest security content into knowledge base",
        category="intel", handler=_ingest,
        usage="/ingest <path_or_text> [--title=...] [--target=...] [--source-type=writeup]",
    ))
    registry.register(Command(
        name="reports", description="Query ingested reports",
        category="intel", handler=_reports,
        usage="/reports [stats|by-vuln|by-target|high-value] [--target=...] [--vuln-class=...] [--min-score=0]",
    ))
    registry.register(Command(
        name="extract", description="AI-powered field extraction",
        category="intel", handler=_extract,
        usage="/extract <field_type> <text_or_slug> [--model=...]",
    ))
    registry.register(Command(
        name="intel-stats", description="Knowledge ingestion statistics",
        category="intel", handler=_intel_stats,
        usage="/intel-stats",
    ))
