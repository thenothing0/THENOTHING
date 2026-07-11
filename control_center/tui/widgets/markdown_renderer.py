"""Pure rendering helpers — the single source of truth for chat + panels.

No widget, no service, no state, no I/O. Every function takes plain data and
returns a Rich renderable. Shared by ``ConversationLog`` (back-compat) and
``ChatView`` so rendering logic lives in exactly one place.

Colours are a fixed, low-saturation "premium dark" palette (Tokyo-night /
VS Code Dark family) applied via Rich markup. Textual theme variables only
exist in TCSS, not in Rich markup, so the conversation body uses these literals
to stay consistent across themes while the surrounding chrome follows the theme.
"""

from __future__ import annotations

import json
from typing import Any

from rich.console import Group, RenderableType
from rich.markdown import Markdown
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

# ── Palette (literal, theme-independent body colours) ──
ACCENT = "#7aa2f7"   # blue   — user / titles
OK = "#9ece6a"       # green  — success / confirmed
WARN = "#e0af68"     # yellow — suspected / warnings
ERR = "#f7768e"      # red    — errors / critical
MUTE = "grey50"      # dim    — system / metadata
INFO = "#7dcfff"     # cyan   — info accents

SEV_COLORS = {
    "critical": ERR,
    "high": ERR,
    "medium": WARN,
    "low": INFO,
    "info": MUTE,
}


def severity_color(sev: str) -> str:
    return SEV_COLORS.get((sev or "info").lower(), MUTE)


# ── Chat message primitives ──

def banner() -> RenderableType:
    return Text.from_markup(
        f"[bold {ACCENT}]HYDRA[/] [dim]v2.0[/] — Cognitive Autonomous Red Team Platform\n"
        "[dim]Type a message or /help for commands.  Ctrl+P palette · Ctrl+Q quit[/]\n"
    )


def user_message(text: str) -> RenderableType:
    """A user turn — a subtle left-accented bubble."""
    body = Text(text or "", style="bold")
    return Panel(
        body,
        border_style=ACCENT,
        padding=(0, 1),
        title="you",
        title_align="right",
        expand=True,
    )


def assistant_message(body: RenderableType, title: str = "hydra") -> RenderableType:
    """An assistant/result turn wrapped in a quiet panel."""
    return Panel(body, border_style="grey35", padding=(0, 1),
                 title=f"[{INFO}]{title}[/]", title_align="left", expand=True)


def system_message(text: str) -> RenderableType:
    return Text.from_markup(f"[{MUTE}]{_esc(text)}[/]")


def error_message(text: str, *, traceback: bool = False) -> RenderableType:
    if traceback:
        from rich.traceback import Traceback
        try:
            return Traceback(show_locals=False, width=None)
        except Exception:
            pass
    return Text.from_markup(f"[bold {ERR}]Error:[/] {_esc(text)}")


# ── Format primitives ──

def markdown(md_text: str) -> RenderableType:
    return Markdown(md_text or "")


def code(src: str, lang: str = "python") -> RenderableType:
    return Syntax(src or "", lang, theme="ansi_dark", word_wrap=True)


def json_block(obj: Any) -> RenderableType:
    try:
        text = json.dumps(obj, indent=2, default=str)
    except Exception:
        text = str(obj)
    return Syntax(text, "json", theme="ansi_dark", word_wrap=True)


def _esc(text: str) -> str:
    """Escape Rich markup in untrusted text."""
    return str(text).replace("[", r"\[")


# ── Autonomous agent rendering ──

_TASK_ICON = {
    "completed": f"[{OK}]✓[/]",
    "failed": f"[{ERR}]✗[/]",
    "running": f"[{ACCENT}]⟳[/]",
    "ready": f"[{INFO}]○[/]",
    "waiting": f"[{MUTE}]·[/]",
    "cancelled": f"[{MUTE}]⊘[/]",
}


def _task_icon(state: str) -> str:
    return _TASK_ICON.get(state, f"[{MUTE}]·[/]")


def agent_started(objective: str, target: str) -> RenderableType:
    tgt = f" → {_esc(target)}" if target else ""
    return Text.from_markup(f"\n[bold {ACCENT}]🤖 Agent[/] started: {_esc(objective)}{tgt}")


def agent_plan_tree(tasks: list[dict], target: str = "") -> RenderableType:
    """Render the execution plan as a dependency tree."""
    tree = Tree(f"[{ACCENT}]Plan[/] [dim]{_esc(target)}[/]")
    children: dict[str, list[dict]] = {}
    roots: list[dict] = []
    for task in tasks:
        deps = task.get("depends_on") or []
        (children.setdefault(deps[0], []).append(task) if deps else roots.append(task))

    def _add(node, task):
        label = _esc(task.get("command") or task.get("description") or "?")
        child = node.add(f"{_task_icon(task.get('state', 'waiting'))} {label}")
        for grandchild in children.get(task.get("id", ""), []):
            _add(child, grandchild)

    for root in roots:
        _add(tree, root)
    return tree


def agent_reasoning(phase: str, thought: str) -> RenderableType:
    return Text.from_markup(f"[{MUTE}]· [{phase}] {_esc(thought)}[/]")


def agent_task_line(state: str, command: str, description: str = "") -> RenderableType:
    label = _esc(command or description)
    return Text.from_markup(f"  {_task_icon(state)} {label}")


def agent_progress(snapshot: dict) -> RenderableType:
    return _kv_panel("Agent Goal", [
        ("Objective", snapshot.get("objective", "")),
        ("State", snapshot.get("state", "")),
        ("Progress", f"{snapshot.get('completion_pct', 0)}%"),
        ("Confidence", snapshot.get("confidence", 0)),
        ("Current", snapshot.get("current_task", "")),
        ("Completed", f"{snapshot.get('completed', 0)}/{snapshot.get('total_tasks', 0)}"),
        ("Blocked", snapshot.get("blocked", 0)),
    ])


def agent_finished(status: str, snapshot: dict | None = None) -> RenderableType:
    color = OK if status == "completed" else (ERR if status == "failed" else WARN)
    parts: list[RenderableType] = [Text.from_markup(
        f"\n[bold {color}]🤖 Agent {status}[/]")]
    if snapshot:
        parts.append(agent_progress(snapshot))
    return Group(*parts)


def _kv_panel(title: str, rows: list[tuple[str, Any]], *, border: str = INFO) -> RenderableType:
    table = Table.grid(padding=(0, 1))
    table.add_column(style=MUTE, justify="right")
    table.add_column()
    for label, value in rows:
        if value in (None, "", []):
            continue
        table.add_row(f"{label}:", _esc(str(value)))
    return Panel(table, title=f"[{ACCENT}]{title}[/]", title_align="left",
                 border_style=border, padding=(0, 1), expand=True)


# ── Result dispatch (every type the backend can hand the UI) ──

def render_result(result: dict) -> RenderableType:
    """Map a command-result dict to a single Rich renderable."""
    rtype = result.get("type", "")
    fn = _DISPATCH.get(rtype)
    if fn is not None:
        return fn(result)
    return Text.from_markup(f"[{MUTE}]{_esc(result)}[/]")


def _help(result: dict) -> RenderableType:
    commands = result.get("commands", [])
    by_cat: dict[str, list] = {}
    for cmd in commands:
        by_cat.setdefault(cmd.get("category", "other"), []).append(cmd)
    parts: list[RenderableType] = [Text.from_markup(f"[bold {ACCENT}]Available Commands[/]")]
    for cat in sorted(by_cat):
        parts.append(Text.from_markup(f"\n[bold {WARN}]{_esc(cat)}[/]"))
        for cmd in by_cat[cat]:
            line = f"  [{OK}]/{_esc(cmd['name'])}[/] — {_esc(cmd.get('description', ''))}"
            if cmd.get("usage"):
                line += f"  [dim]{_esc(cmd['usage'])}[/]"
            parts.append(Text.from_markup(line))
    return Group(*parts)


def _status(result: dict) -> RenderableType:
    return _kv_panel("System Status", [
        ("Platform", result.get("platform", "?")),
        ("Version", result.get("version", "?")),
        ("Status", result.get("status", "?")),
        ("Data dir", result.get("data_dir", "?")),
    ])


def _tools(result: dict) -> RenderableType:
    tools = result.get("tools", {})
    parts: list[RenderableType] = [Text.from_markup(f"[bold {ACCENT}]Security Tools[/]")]
    for name, available in sorted(tools.items()):
        icon = f"[{OK}]●[/]" if available else f"[{ERR}]○[/]"
        parts.append(Text.from_markup(f"  {icon} {_esc(name)}"))
    return Group(*parts)


def _findings_list(result: dict) -> RenderableType:
    findings = result.get("findings", [])
    if not findings:
        return Text.from_markup(f"[{MUTE}]No findings.[/]")
    parts: list[RenderableType] = [Text.from_markup(f"[bold {ACCENT}]Findings ({len(findings)})[/]")]
    for f in findings:
        sev = f.get("severity", "info")
        color = severity_color(sev)
        fid = f.get("finding_id", f.get("id", "?"))
        parts.append(Text.from_markup(
            f"  [{color}]{sev.upper():8s}[/] {_esc(fid)} — {_esc(f.get('title', ''))}"))
    return Group(*parts)


def _finding_detail(result: dict) -> RenderableType:
    f = result.get("finding", {})
    if not f:
        return Text.from_markup(f"[{MUTE}]No finding data.[/]")
    rows = [
        ("ID", f.get("finding_id", f.get("id", "?"))),
        ("Severity", f.get("severity", "info")),
        ("State", f.get("state", "?")),
        ("Class", f.get("vuln_class", "?")),
        ("Endpoint", f.get("endpoint", "?")),
        ("Impact", f.get("impact", "")),
        ("Remediate", f.get("remediation", "")),
    ]
    return _kv_panel(f.get("title", "Finding"), rows,
                     border=severity_color(f.get("severity", "info")))


def _finding_transitioned(result: dict) -> RenderableType:
    return Text.from_markup(
        f"[{OK}]Finding {_esc(result.get('finding_id', '?'))} → "
        f"{_esc(result.get('to_state', '?'))}[/]")


def _search(result: dict) -> RenderableType:
    query = result.get("query", "")
    results = result.get("results", [])
    parts: list[RenderableType] = [Text.from_markup(f"[bold {ACCENT}]Results for \"{_esc(query)}\"[/]")]
    if not results:
        parts.append(Text.from_markup(f"[{MUTE}]No results.[/]"))
    for r in results:
        slug = r.get("slug", r.get("page", "?"))
        parts.append(Text.from_markup(
            f"  [{OK}]{r.get('score', 0):.1f}[/]  {_esc(slug)} — {_esc(r.get('title', slug))}"))
    return Group(*parts)


def _learn_recorded(result: dict) -> RenderableType:
    return Text.from_markup(f"[{OK}]Lesson recorded.[/]")


def _scope_register(result: dict) -> RenderableType:
    return _kv_panel("Scope registered", [
        ("Program", result.get("program", "?")),
        ("Platform", result.get("platform", "?")),
        ("In scope", result.get("in_scope", "?")),
    ], border=OK)


def _scope_load(result: dict) -> RenderableType:
    return Text.from_markup(f"[{MUTE}]Loading scope from {_esc(result.get('url', '?'))}...[/]")


def _recon_result(result: dict) -> RenderableType:
    rows = [("Status", result.get("status", "?"))]
    if result.get("tools"):
        rows.append(("Tools", ", ".join(result["tools"])))
    if result.get("note"):
        rows.append(("Note", result["note"]))
    return _kv_panel(f"Recon: {result.get('target', '?')}", rows)


def _scan_result(result: dict) -> RenderableType:
    confirmed = result.get("confirmed_findings", [])
    suspected = result.get("suspected", [])
    parts: list[RenderableType] = [Text.from_markup(
        f"[bold {ACCENT}]Scan: {_esc(result.get('target', '?'))}[/] "
        f"[{result.get('vuln_class', '?')}]\n"
        f"  Confirmed: [{OK}]{len(confirmed)}[/]  Suspected: [{WARN}]{len(suspected)}[/]")]
    for f in confirmed[:5]:
        parts.append(Text.from_markup(f"  [{OK}]●[/] {_esc(f.get('title', f.get('id', '?')))}"))
    for f in suspected[:3]:
        parts.append(Text.from_markup(f"  [{WARN}]○[/] {_esc(f.get('title', f.get('id', '?')))}"))
    return Group(*parts)


def _workflow_status(result: dict) -> RenderableType:
    wf = result.get("workflow")
    if not wf:
        return Text.from_markup(f"[{MUTE}]No active workflow.[/]")
    return _kv_panel(f"Workflow {wf.get('run_id', '?')}", [
        ("Target", wf.get("target", "?")),
        ("State", wf.get("state", "?")),
    ])


def _engage_list(result: dict) -> RenderableType:
    engagements = result.get("engagements", [])
    if not engagements:
        return Text.from_markup(f"[{MUTE}]No engagements. Use /engage to create one.[/]")
    parts: list[RenderableType] = [Text.from_markup(f"[bold {ACCENT}]Engagements ({len(engagements)})[/]")]
    for e in engagements:
        eid = e.get("engagement_id", e.get("id", "?"))
        parts.append(Text.from_markup(
            f"  [{OK}]{_esc(eid)}[/] — {_esc(e.get('name', ''))} ({_esc(e.get('client', ''))})"))
    return Group(*parts)


def _engage_switch(result: dict) -> RenderableType:
    return Text.from_markup(f"[{OK}]Switched to engagement:[/] {_esc(result.get('engagement_id', '?'))}")


def _coverage_next(result: dict) -> RenderableType:
    targets = result.get("targets", [])
    if not targets:
        return Text.from_markup(f"[{MUTE}]No untested targets remaining.[/]")
    parts: list[RenderableType] = [Text.from_markup(f"[bold {ACCENT}]Next targets ({len(targets)})[/]")]
    for t in targets:
        parts.append(Text.from_markup(
            f"  [{WARN}]{t.get('priority', 0):.1f}[/] {_esc(t.get('endpoint', '?'))} "
            f"— {_esc(t.get('vuln_class', '?'))}"))
    return Group(*parts)


def _kb_lint(result: dict) -> RenderableType:
    data = result.get("result", {})
    orphans = data.get("orphans", [])
    return _kv_panel("Knowledge Health", [
        ("Pages", data.get("total_pages", 0)),
        ("Orphans", len(orphans)),
        ("Dangling", len(data.get("dangling_links", []))),
    ])


def _wiki_page(result: dict) -> RenderableType:
    slug = result.get("slug", "?")
    page = result.get("page")
    if not page:
        return Text.from_markup(f"[{MUTE}]Page not found: {_esc(slug)}[/]")
    if isinstance(page, dict):
        return Text.from_markup(
            f"\n[bold {ACCENT}]{_esc(page.get('title', slug))}[/] "
            f"[dim]({_esc(page.get('type', '?'))}/{_esc(page.get('stage', '?'))})[/]\n"
            f"  [dim]Opened in context. Press Escape to close.[/]")
    return Text.from_markup(f"\n[bold {ACCENT}]{_esc(slug)}[/]\n[dim]Opened in context.[/]")


def _chat(result: dict) -> RenderableType:
    msg = result.get("message", "")
    return assistant_message(Markdown(msg)) if msg else Text("")


def _plugin_result(result: dict) -> RenderableType:
    data = result.get("result", {})
    msg = data.get("message", data.get("status", str(data))) if isinstance(data, dict) else str(data)
    return Text.from_markup(
        f"[bold #bb9af7]{_esc(result.get('plugin', '?'))}[/] → {_esc(msg)}")


_DISPATCH = {
    "help": _help,
    "status": _status,
    "tools": _tools,
    "findings_list": _findings_list,
    "finding_detail": _finding_detail,
    "finding_transitioned": _finding_transitioned,
    "search_results": _search,
    "recall_results": _search,
    "learn_recorded": _learn_recorded,
    "scope_register": _scope_register,
    "scope_load": _scope_load,
    "recon_result": _recon_result,
    "scan_result": _scan_result,
    "workflow_status": _workflow_status,
    "engage_list": _engage_list,
    "engage_switch": _engage_switch,
    "coverage_next": _coverage_next,
    "kb_lint": _kb_lint,
    "wiki_page": _wiki_page,
    "chat": _chat,
    "plugin_result": _plugin_result,
}
