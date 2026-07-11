"""Reasoning, Context Intel, and Dual Intel commands (Phase 10 Batch 2)."""

from hydra.commands.registry import Command, CommandRegistry
from hydra.commands.result import CommandResult


def _reasoning(args, kwargs, ctx):
    if not args:
        stats = ctx.services.reasoning.get_stats()
        return CommandResult.success({"type": "reasoning_stats", **stats})
    subcmd = args[0]
    if subcmd == "hypotheses":
        target = kwargs.get("target", "")
        state = kwargs.get("state", "")
        hyps = ctx.services.reasoning.list_hypotheses(state=state, target=target)
        return CommandResult.success({"type": "reasoning_hypotheses", "hypotheses": hyps})
    if subcmd == "generate":
        target = kwargs.get("target", "")
        mode = kwargs.get("mode", "abductive")
        obs = []
        for a in args[1:]:
            parts = a.split(":", 1)
            if len(parts) == 2:
                obs.append({"type": parts[0], "value": parts[1]})
        if not obs:
            obs = [{"type": "generic", "value": target or "unknown"}]
        result = ctx.services.reasoning.generate_hypotheses(obs, target=target, mode=mode)
        return CommandResult.success({"type": "reasoning_generated", **result})
    if subcmd == "update" and len(args) > 1:
        hyp_id = args[1]
        evidence = kwargs.get("evidence", "manual observation")
        supports = kwargs.get("supports", "true").lower() == "true"
        result = ctx.services.reasoning.update_hypothesis(hyp_id, evidence, supports)
        return CommandResult.success({"type": "reasoning_updated", **result})
    return CommandResult.error(
        "Usage: /reasoning [generate --target T|hypotheses|update <id> --evidence E]"
    )


def _context(args, kwargs, ctx):
    if not args:
        stats = ctx.services.context_intel.get_stats()
        return CommandResult.success({"type": "context_stats", **stats})
    subcmd = args[0]
    if subcmd == "enrich":
        target = kwargs.get("target", "")
        action = kwargs.get("action", "")
        vuln_class = kwargs.get("vuln_class", "")
        result = ctx.services.context_intel.enrich(
            target=target, action=action, vuln_class=vuln_class,
        )
        return CommandResult.success({"type": "context_enriched", **result})
    if subcmd == "history" and len(args) > 1:
        result = ctx.services.context_intel.get_target_history(args[1])
        return CommandResult.success({"type": "context_history", **result})
    if subcmd == "vuln" and len(args) > 1:
        result = ctx.services.context_intel.get_vuln_intel(args[1])
        return CommandResult.success({"type": "context_vuln_intel", **result})
    return CommandResult.error(
        "Usage: /context [enrich --target T|history <target>|vuln <class>]"
    )


def _dualintel(args, kwargs, ctx):
    if not args:
        stats = ctx.services.dual_intel.get_stats()
        return CommandResult.success({"type": "dualintel_stats", **stats})
    subcmd = args[0]
    if subcmd == "analyze" and len(args) > 1:
        vuln_class = args[1]
        target = kwargs.get("target", "")
        severity = kwargs.get("severity", "medium")
        result = ctx.services.dual_intel.analyze(
            vuln_class, target=target, severity=severity,
        )
        return CommandResult.success({"type": "dualintel_analysis", **result})
    if subcmd == "offensive" and len(args) > 1:
        result = ctx.services.dual_intel.get_offensive_intel(args[1])
        return CommandResult.success({"type": "dualintel_offensive", **result})
    if subcmd == "defensive" and len(args) > 1:
        result = ctx.services.dual_intel.get_defensive_intel(args[1])
        return CommandResult.success({"type": "dualintel_defensive", **result})
    if subcmd == "compare" and len(args) > 1:
        result = ctx.services.dual_intel.compare_perspectives(args[1])
        return CommandResult.success({"type": "dualintel_comparison", **result})
    return CommandResult.error(
        "Usage: /dualintel [analyze <class>|offensive <class>|defensive <class>|compare <class>]"
    )


def register_reasoning_commands(registry: CommandRegistry):
    registry.register(Command(
        name="reasoning", description="Causal reasoning and hypothesis engine",
        category="intel", handler=_reasoning,
        usage="/reasoning [generate|hypotheses|update <id>]",
    ))
    registry.register(Command(
        name="context", description="Pre-action context intelligence",
        category="intel", handler=_context,
        usage="/context [enrich --target T|history <target>|vuln <class>]",
    ))
    registry.register(Command(
        name="dualintel", description="Dual offensive + defensive intelligence",
        category="intel", handler=_dualintel,
        usage="/dualintel [analyze <class>|offensive|defensive|compare]",
    ))
