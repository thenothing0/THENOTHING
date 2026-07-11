"""Knowledge Sync, Copilot, Campaign commands (Phase 10 Batch 4)."""

from hydra.commands.registry import Command, CommandRegistry
from hydra.commands.result import CommandResult


def _sync(args, kwargs, ctx):
    if not args:
        stats = ctx.services.knowledge_sync.get_stats()
        return CommandResult.success({"type": "sync_stats", **stats})
    subcmd = args[0]
    if subcmd == "snapshot":
        sources = args[1:] if len(args) > 1 else None
        result = ctx.services.knowledge_sync.create_snapshot(sources)
        return CommandResult.success({**result, "type": "sync_snapshot"})
    if subcmd == "push" and len(args) > 1:
        peer_id = args[1]
        snap_id = kwargs.get("snapshot", "")
        result = ctx.services.knowledge_sync.sync_to_peer(peer_id, snap_id)
        return CommandResult.success({**result, "type": "sync_pushed"})
    if subcmd == "pull" and len(args) > 1:
        peer_id = args[1]
        result = ctx.services.knowledge_sync.sync_from_peer(peer_id)
        return CommandResult.success({**result, "type": "sync_pulled"})
    if subcmd == "peers":
        peers = ctx.services.knowledge_sync.list_peers()
        return CommandResult.success({"type": "sync_peers", "peers": peers})
    if subcmd == "history":
        history = ctx.services.knowledge_sync.get_sync_history()
        return CommandResult.success({"type": "sync_history", "history": history})
    return CommandResult.error(
        "Usage: /sync [snapshot|push <peer>|pull <peer>|peers|history]"
    )


def _copilot(args, kwargs, ctx):
    if not args:
        stats = ctx.services.copilot.get_stats()
        return CommandResult.success({"type": "copilot_stats", **stats})
    subcmd = args[0]
    if subcmd == "suggest":
        context = {}
        if "target" in kwargs:
            context["target"] = kwargs["target"]
        if "vuln_class" in kwargs:
            context["vuln_class"] = kwargs["vuln_class"]
        if "phase" in kwargs:
            context["phase"] = kwargs["phase"]
        result = ctx.services.copilot.suggest(context)
        return CommandResult.success({"type": "copilot_suggestions", **result})
    if subcmd == "mode" and len(args) > 1:
        result = ctx.services.copilot.set_mode(args[1])
        return CommandResult.success({**result, "type": "copilot_mode"})
    if subcmd == "explain" and len(args) > 1:
        result = ctx.services.copilot.explain(args[1])
        return CommandResult.success({**result, "type": "copilot_explain"})
    if subcmd == "context":
        result = ctx.services.copilot.get_context()
        return CommandResult.success({"type": "copilot_context", **result})
    return CommandResult.error(
        "Usage: /copilot [suggest|mode <passive|active|autonomous>|explain <topic>|context]"
    )


def _campaign(args, kwargs, ctx):
    if not args:
        stats = ctx.services.campaign.get_stats()
        return CommandResult.success({"type": "campaign_stats", **stats})
    subcmd = args[0]
    if subcmd == "create" and len(args) > 1:
        target = args[1]
        ctype = kwargs.get("type", "bounty_hunt")
        result = ctx.services.campaign.create_campaign(target, campaign_type=ctype)
        return CommandResult.success({**result, "type": "campaign_created"})
    if subcmd == "start" and len(args) > 1:
        result = ctx.services.campaign.start_campaign(args[1])
        return CommandResult.success({**result, "type": "campaign_started"})
    if subcmd == "advance" and len(args) > 1:
        result = ctx.services.campaign.advance_phase(args[1])
        return CommandResult.success({**result, "type": "campaign_advanced"})
    if subcmd == "pause" and len(args) > 1:
        result = ctx.services.campaign.pause_campaign(args[1])
        return CommandResult.success({**result, "type": "campaign_paused"})
    if subcmd == "cancel" and len(args) > 1:
        result = ctx.services.campaign.cancel_campaign(args[1])
        return CommandResult.success({**result, "type": "campaign_cancelled"})
    if subcmd == "list":
        state = kwargs.get("state", "")
        campaigns = ctx.services.campaign.list_campaigns(state=state)
        return CommandResult.success({"type": "campaign_list", "campaigns": campaigns})
    if subcmd == "get" and len(args) > 1:
        result = ctx.services.campaign.get_campaign(args[1])
        return CommandResult.success({**result, "type": "campaign_detail"})
    return CommandResult.error(
        "Usage: /campaign [create <target>|start <id>|advance <id>|pause <id>|cancel <id>|list|get <id>]"
    )


def register_campaign_commands(registry: CommandRegistry):
    registry.register(Command(
        name="sync", description="Knowledge synchronization",
        category="intel", handler=_sync,
        usage="/sync [snapshot|push <peer>|pull <peer>|peers|history]",
    ))
    registry.register(Command(
        name="copilot", description="AI-assisted security copilot",
        category="intel", handler=_copilot,
        usage="/copilot [suggest|mode|explain <topic>|context]",
    ))
    registry.register(Command(
        name="campaign", description="Autonomous campaign management",
        category="intel", handler=_campaign,
        usage="/campaign [create|start|advance|pause|cancel|list|get]",
    ))
