"""Infrastructure commands: /theme, /monitor, /providers, /models, /updates."""

from hydra.commands.registry import Command, CommandRegistry
from hydra.commands.result import CommandResult


def _theme(args, kwargs, ctx):
    from control_center.tui.themes import list_themes, AVAILABLE_THEMES
    if not args:
        themes = list_themes()
        return CommandResult.success({"type": "theme_list", "themes": themes})
    name = args[0]
    if name not in AVAILABLE_THEMES:
        return CommandResult.error(f"Unknown theme: {name}. Available: {', '.join(AVAILABLE_THEMES)}")
    return CommandResult.success({"type": "theme_switch", "theme": name})


def _monitor(args, kwargs, ctx):
    snapshot = ctx.services.monitor.get_snapshot()
    return CommandResult.success({"type": "monitor", **snapshot})


def _providers(args, kwargs, ctx):
    from hydra.ai.providers import ProviderManager
    pm = ProviderManager()
    providers = pm.list_providers()
    health = pm.get_all_health()
    return CommandResult.success({
        "type": "providers",
        "providers": providers,
        "health": health,
    })


def _models(args, kwargs, ctx):
    from hydra.ai.providers import ProviderManager
    pm = ProviderManager()
    if args:
        provider_id = args[0]
        models = pm.discover_models(provider_id)
        return CommandResult.success({
            "type": "models",
            "provider": provider_id,
            "models": models,
        })
    active = pm.get_active_info()
    return CommandResult.success({
        "type": "models",
        "provider": active.get("provider", "?"),
        "models": pm.discover_models(active.get("provider", "")),
        "active_model": active.get("model", "?"),
    })


def _updates(args, kwargs, ctx):
    force = "force" in args or "--force" in args
    result = ctx.services.updates.check(force=force)
    return CommandResult.success({"type": "updates", **result})


def register_infrastructure_commands(registry: CommandRegistry):
    registry.register(Command(
        name="theme", description="Switch terminal theme or list available themes",
        category="system", usage="/theme [name]", handler=_theme,
    ))
    registry.register(Command(
        name="monitor", description="Show runtime monitoring snapshot",
        category="system", usage="/monitor", handler=_monitor,
    ))
    registry.register(Command(
        name="providers", description="List AI providers and their health",
        category="system", usage="/providers", handler=_providers,
    ))
    registry.register(Command(
        name="models", description="List models for a provider",
        category="system", usage="/models [provider]", handler=_models,
    ))
    registry.register(Command(
        name="updates", description="Check for platform updates",
        category="system", usage="/updates [--force]", handler=_updates,
    ))
