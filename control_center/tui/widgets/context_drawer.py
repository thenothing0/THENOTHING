"""Context drawer — slide-in right panel for detail views.

Shows finding details, wiki pages, tool configs, etc.
Toggled by selecting an item or pressing Escape to close.
"""

from __future__ import annotations

from rich.markdown import Markdown
from textual.containers import VerticalScroll
from textual.widgets import Static


class ContextDrawer(VerticalScroll):
    """Right-side detail panel. Content is set by the app based on WorkspaceState."""

    DEFAULT_CSS = """
    ContextDrawer {
        width: 45;
        background: #161b22;
        border-left: solid #30363d;
        padding: 1 2;
        display: none;
    }
    ContextDrawer.open {
        display: block;
    }
    ContextDrawer .drawer-title {
        text-style: bold;
        color: #58a6ff;
        margin-bottom: 1;
    }
    ContextDrawer .drawer-label {
        color: #8b949e;
    }
    ContextDrawer .drawer-value {
        color: #c9d1d9;
        margin-bottom: 1;
    }
    """

    def show_finding(self, finding: dict):
        """Render a finding detail."""
        self.clear()
        self.mount(Static("[bold cyan]Finding Detail[/]", classes="drawer-title"))
        fields = [
            ("ID", finding.get("finding_id", finding.get("id", "?"))),
            ("Title", finding.get("title", "")),
            ("Severity", finding.get("severity", "info")),
            ("State", finding.get("state", "draft")),
            ("Class", finding.get("vuln_class", "")),
            ("Endpoint", finding.get("endpoint", "")),
            ("Method", finding.get("method", "")),
            ("Parameter", finding.get("parameter", "")),
            ("CWE", finding.get("cwe", "")),
            ("OWASP", finding.get("owasp", "")),
        ]
        for label, value in fields:
            if value:
                self.mount(Static(f"[dim]{label}:[/]", classes="drawer-label"))
                self.mount(Static(str(value), classes="drawer-value"))

        if finding.get("impact"):
            self.mount(Static("[dim]Impact:[/]", classes="drawer-label"))
            self.mount(Static(finding["impact"], classes="drawer-value"))

        if finding.get("remediation"):
            self.mount(Static("[dim]Remediation:[/]", classes="drawer-label"))
            self.mount(Static(finding["remediation"], classes="drawer-value"))

        self.add_class("open")

    def show_wiki_page(self, page: dict):
        """Render a wiki page."""
        self.clear()
        title = page.get("title", page.get("slug", "?"))
        self.mount(Static(f"[bold cyan]{title}[/]", classes="drawer-title"))

        if page.get("type"):
            self.mount(Static(f"[dim]Type: {page['type']}[/]"))
        if page.get("stage"):
            self.mount(Static(f"[dim]Stage: {page['stage']}[/]"))

        content = page.get("content", "")
        if content:
            self.mount(Static(Markdown(content)))

        links = page.get("links", [])
        if links:
            self.mount(Static("\n[dim]Links:[/]"))
            for link in links:
                self.mount(Static(f"  [cyan]{link}[/]"))

        self.add_class("open")

    def show_agent(self, snapshot: dict):
        """Render a live agent goal snapshot (current task, progress, confidence)."""
        self.clear()
        self.mount(Static("[bold cyan]🤖 Agent[/]", classes="drawer-title"))
        rows = [
            ("Objective", snapshot.get("objective", "")),
            ("State", snapshot.get("state", "")),
            ("Progress", f"{snapshot.get('completion_pct', 0)}%"),
            ("Confidence", snapshot.get("confidence", 0)),
            ("Current task", snapshot.get("current_task", "")),
            ("Completed", f"{snapshot.get('completed', 0)}/{snapshot.get('total_tasks', 0)}"),
            ("Failed", snapshot.get("failed", 0)),
            ("Blocked", snapshot.get("blocked", 0)),
        ]
        for label, value in rows:
            if value not in (None, ""):
                self.mount(Static(f"[dim]{label}:[/]", classes="drawer-label"))
                self.mount(Static(str(value), classes="drawer-value"))
        self.add_class("open")

    def show_text(self, title: str, text: str):
        """Render arbitrary text content."""
        self.clear()
        self.mount(Static(f"[bold cyan]{title}[/]", classes="drawer-title"))
        self.mount(Static(text))
        self.add_class("open")

    def close(self):
        self.remove_class("open")

    def clear(self):
        for child in list(self.children):
            child.remove()
