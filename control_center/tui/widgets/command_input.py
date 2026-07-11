"""Command input — multiline prompt with history, reverse search and completion.

Re-based on ``TextArea`` for a Claude-Code-style multiline prompt while keeping
the original public surface (``CommandInput``, ``CommandSubmitted``,
``set_completion_provider``/``set_completions``/``save_history``/``get_history``,
the module-level ``_ARGUMENT_HINTS``, and ``Path``-based history persistence).

Keys: Enter = send · Shift+Enter = newline · ↑/↓ = history (single line) ·
Ctrl+R = reverse search · Tab = completion.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Callable

from textual.message import Message
from textual.widgets import TextArea

logger = logging.getLogger("control_center.tui.command_input")


class CommandSubmitted(Message):
    """Fired when the user presses Enter."""

    def __init__(self, value: str):
        super().__init__()
        self.value = value


class CommandInput(TextArea):
    """Multiline prompt with shell-like history, reverse search and completion."""

    HISTORY_FILE = ".hydra_command_history"
    MAX_HISTORY = 1000

    def __init__(self, **kw):
        kw.setdefault("show_line_numbers", False)
        kw.setdefault("soft_wrap", True)
        kw.setdefault("tab_behavior", "focus")
        super().__init__(**kw)
        self._history: list[str] = []
        self._history_idx: int = -1
        self._saved_input: str = ""

        self._completions: list[str] = []
        self._completion_idx: int = -1
        self._completion_provider: Callable[[str], list[str]] | None = None

        self._reverse_search_active: bool = False
        self._reverse_search_query: str = ""
        self._reverse_search_matches: list[str] = []
        self._reverse_search_idx: int = -1

        self._load_history()

    # ── History persistence ──

    def _load_history(self) -> None:
        try:
            path = Path("data") / self.HISTORY_FILE
            if path.exists():
                lines = path.read_text().strip().split("\n")
                self._history = [ln for ln in lines if ln][-self.MAX_HISTORY:]
        except Exception:
            pass

    def save_history(self) -> None:
        try:
            path = Path("data") / self.HISTORY_FILE
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("\n".join(self._history[-self.MAX_HISTORY:]))
        except Exception:
            pass

    def get_history(self) -> list[str]:
        return list(self._history)

    # ── Completion provider ──

    def set_completion_provider(self, provider: Callable[[str], list[str]]) -> None:
        self._completion_provider = provider

    def set_completions(self, completions: list[str]) -> None:
        self._completions = completions
        self._completion_idx = -1

    # ── Text helpers ──

    def _set_text(self, value: str) -> None:
        self.text = value
        try:
            self.move_cursor(self.document.end)
        except Exception:
            pass

    # ── Key handling ──

    def on_key(self, event) -> None:
        if self._reverse_search_active:
            self._handle_reverse_search_key(event)
            return

        key = event.key
        if key == "enter":
            event.prevent_default()
            event.stop()
            self._submit()
        elif key == "shift+enter":
            event.prevent_default()
            event.stop()
            self.insert("\n")
        elif key == "tab":
            event.prevent_default()
            event.stop()
            self._do_completion()
        elif key == "ctrl+r":
            event.prevent_default()
            event.stop()
            self._enter_reverse_search()
        elif key in ("up", "down") and "\n" not in self.text:
            event.prevent_default()
            event.stop()
            self._navigate_history(-1 if key == "up" else 1)

    def _submit(self) -> None:
        text = self.text.strip()
        if not text:
            return
        if not self._history or self._history[-1] != text:
            self._history.append(text)
        self._history_idx = -1
        self._saved_input = ""
        self.text = ""
        self.post_message(CommandSubmitted(text))

    # ── History navigation ──

    def _navigate_history(self, direction: int) -> None:
        if not self._history:
            return

        if self._history_idx == -1:
            self._saved_input = self.text
            if direction == -1:
                self._history_idx = len(self._history) - 1
            else:
                return
        else:
            new_idx = self._history_idx + direction
            if new_idx < 0:
                new_idx = 0
            elif new_idx >= len(self._history):
                self._history_idx = -1
                self._set_text(self._saved_input)
                return
            self._history_idx = new_idx

        self._set_text(self._history[self._history_idx])

    # ── Reverse search ──

    def _enter_reverse_search(self) -> None:
        self._reverse_search_active = True
        self._reverse_search_query = ""
        self._reverse_search_matches = []
        self._reverse_search_idx = -1
        self._saved_input = self.text
        self._update_reverse_search_display()

    def _exit_reverse_search(self, accept: bool = False) -> None:
        self._reverse_search_active = False
        self.border_title = ""
        if accept and self._reverse_search_matches and self._reverse_search_idx >= 0:
            self._set_text(self._reverse_search_matches[self._reverse_search_idx])
        elif not accept:
            self._set_text(self._saved_input)

    def _handle_reverse_search_key(self, event) -> None:
        key = event.key
        if key == "escape":
            self._exit_reverse_search(accept=False)
            event.prevent_default()
            event.stop()
        elif key == "enter":
            self._exit_reverse_search(accept=True)
            event.prevent_default()
            event.stop()
        elif key == "ctrl+r":
            if self._reverse_search_matches and self._reverse_search_idx < len(self._reverse_search_matches) - 1:
                self._reverse_search_idx += 1
                self._update_reverse_search_display()
            event.prevent_default()
            event.stop()
        elif key == "backspace":
            if self._reverse_search_query:
                self._reverse_search_query = self._reverse_search_query[:-1]
                self._do_reverse_search()
            event.prevent_default()
            event.stop()
        elif len(event.character or "") == 1 and event.character.isprintable():
            self._reverse_search_query += event.character
            self._do_reverse_search()
            event.prevent_default()
            event.stop()

    def _do_reverse_search(self) -> None:
        query = self._reverse_search_query.lower()
        self._reverse_search_matches = [h for h in reversed(self._history) if query in h.lower()]
        self._reverse_search_idx = 0 if self._reverse_search_matches else -1
        self._update_reverse_search_display()

    def _update_reverse_search_display(self) -> None:
        q = self._reverse_search_query
        if self._reverse_search_matches and self._reverse_search_idx >= 0:
            self._set_text(self._reverse_search_matches[self._reverse_search_idx])
            self.border_title = f"(reverse-search)`{q}'"
        else:
            failing = "failing " if q else ""
            self.border_title = f"({failing}reverse-search)`{q}'"

    # ── Intelligent completion ──

    def _do_completion(self) -> None:
        text = self.text
        if self._completion_provider and text.startswith("/"):
            candidates = self._completion_provider(text)
            if candidates:
                self._completions = candidates
                self._completion_idx = -1

        if text.startswith("/") and " " not in text:
            self._cycle_command_completion(text)
        elif text.startswith("/") and " " in text:
            self._cycle_argument_completion(text)
        else:
            self._cycle_completion()

    def _cycle_command_completion(self, text: str) -> None:
        partial = text[1:]
        matches = [c for c in self._completions if c.startswith(partial)]
        if not matches:
            matches = [c for c in self._completions if partial in c]
        if len(matches) == 1:
            self._set_text("/" + matches[0] + " ")
        elif matches:
            self._completion_idx = (self._completion_idx + 1) % len(matches)
            self._set_text("/" + matches[self._completion_idx])

    def _cycle_argument_completion(self, text: str) -> None:
        parts = text.split()
        cmd = parts[0][1:] if parts else ""
        arg_hints = _ARGUMENT_HINTS.get(cmd, [])
        if not arg_hints:
            return
        current_arg = parts[-1] if len(parts) > 1 else ""
        matches = [h for h in arg_hints if h.startswith(current_arg)]
        if matches:
            self._completion_idx = (self._completion_idx + 1) % len(matches)
            parts[-1] = matches[self._completion_idx]
            self._set_text(" ".join(parts))

    def _cycle_completion(self) -> None:
        if not self._completions:
            return
        self._completion_idx = (self._completion_idx + 1) % len(self._completions)
        self._set_text("/" + self._completions[self._completion_idx])


_ARGUMENT_HINTS: dict[str, list[str]] = {
    "recon": ["--depth=3", "--depth=5", "--depth=1"],
    "scan": ["xss", "sqli", "ssrf", "ssti", "lfi", "open_redirect", "--context=any", "--context=html_body"],
    "attack": ["--classes=xss,sqli", "--classes=xss,sqli,ssrf,ssti"],
    "scope": ["register", "load", "--platform=hackerone", "--platform=bugcrowd", "--platform=yeswehack"],
    "finding": ["--severity=critical", "--severity=high", "--severity=medium", "--severity=low"],
    "learn": ["--tier=project", "--tier=personal", "--tier=cross", "--tier=org"],
    "next": ["--limit=5", "--limit=10", "--limit=20"],
    "session": ["save", "load", "list", "delete"],
    "engage": ["create", "list", "switch"],
    "workflow": ["create", "status", "advance"],
}
