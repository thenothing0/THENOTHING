"""Command palette (Ctrl+P / Ctrl+K) — fuzzy search across the workspace.

Searches commands, workflows, plugins, themes, recent targets, command history,
and offers a knowledge-search action. Feeds Textual's native command palette via
a Provider. Selecting a hit calls back into the App (``fill_prompt`` /
``apply_theme`` / ``run_command``) — the provider itself performs no scans and no
blocking work beyond cheap registry/list lookups.
"""

from __future__ import annotations

from functools import partial

from textual.command import DiscoveryHit, Hit, Hits, Provider

from control_center.tui.themes.native import HYDRA_THEMES


class HydraCommandProvider(Provider):
    """Fuzzy provider over commands, workflows, plugins, themes, targets, history."""

    async def discover(self) -> Hits:
        app = self.app
        api = getattr(app, "api", None)
        if api is None:
            return
        for cmd in api.list_commands()[:20]:
            yield DiscoveryHit(
                f"/{cmd.name} — {cmd.description}",
                partial(app.fill_prompt, f"/{cmd.name} "),
                text=f"/{cmd.name}",
                help=cmd.description,
            )

    async def search(self, query: str) -> Hits:
        app = self.app
        matcher = self.matcher(query)
        q = query.strip()

        # Commands
        api = getattr(app, "api", None)
        if api is not None:
            for cmd in api.list_commands():
                text = f"/{cmd.name}"
                score = matcher.match(f"{text} {cmd.description}")
                if score > 0:
                    yield Hit(score, matcher.highlight(text),
                              partial(app.fill_prompt, f"/{cmd.name} "),
                              text=text, help=cmd.description)

        # Themes
        for theme in HYDRA_THEMES:
            label = f"theme: {theme}"
            score = matcher.match(label)
            if score > 0:
                yield Hit(score, matcher.highlight(label),
                          partial(app.apply_theme, theme),
                          text=label, help="Switch theme")

        # Workflows
        try:
            for tpl in app.facade.list_workflow_templates():
                tid = tpl.get("id", "")
                label = f"workflow: {tid}"
                score = matcher.match(label)
                if score > 0:
                    yield Hit(score, matcher.highlight(label),
                              partial(app.fill_prompt, f"/workflow create {tid} "),
                              text=label, help=tpl.get("description", ""))
        except Exception:
            pass

        # Recent targets
        for tgt in list(getattr(app.state, "recent_targets", []) or [])[:10]:
            label = f"target: {tgt}"
            score = matcher.match(label)
            if score > 0:
                yield Hit(score, matcher.highlight(label),
                          partial(app.fill_prompt, f"/recon {tgt}"),
                          text=label, help="Recent target")

        # Plugins
        try:
            from hydra.plugins.plugin_loader import PluginLoader
            for plugin in PluginLoader().discover():
                label = f"plugin: {plugin.plugin_id}"
                score = matcher.match(label)
                if score > 0:
                    yield Hit(score, matcher.highlight(label),
                              partial(app.fill_prompt, f"/{plugin.plugin_id} "),
                              text=label, help=getattr(plugin, "description", ""))
        except Exception:
            pass

        # Command history
        try:
            for item in reversed(app.command_history()[-30:]):
                score = matcher.match(item)
                if score > 0:
                    yield Hit(score, matcher.highlight(item),
                              partial(app.fill_prompt, item),
                              text=item, help="History")
        except Exception:
            pass

        # Knowledge search action
        if q and not q.startswith("/"):
            label = f"Search knowledge: {q}"
            yield Hit(1.0, label, partial(app.run_command, f"/search {q}"),
                      text=label, help="Run /search")
