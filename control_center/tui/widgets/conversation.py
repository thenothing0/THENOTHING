"""Conversation log — back-compat renderer over ``markdown_renderer``.

The live chat surface in the app is :class:`~control_center.tui.widgets.chat_view.ChatView`.
``ConversationLog`` is retained as the stable, test-facing widget: it keeps the
same public API (``add_user_input``/``add_system``/``add_error``/``add_result``/
``add_markdown``) and simply routes every render through the shared
``markdown_renderer`` so there is exactly one source of rendering logic.
"""

from __future__ import annotations

from textual.widgets import RichLog

from control_center.tui.widgets import markdown_renderer as mr


class ConversationLog(RichLog):
    """Scrollable output log — delegates all rendering to ``markdown_renderer``."""

    DEFAULT_CSS = """
    ConversationLog {
        background: $surface;
        scrollbar-size: 1 1;
    }
    """

    def on_mount(self) -> None:
        self.write(mr.banner())

    def add_user_input(self, text: str) -> None:
        self.write(mr.user_message(text))

    def add_system(self, text: str) -> None:
        self.write(mr.system_message(text))

    def add_error(self, text: str) -> None:
        self.write(mr.error_message(text))

    def add_markdown(self, md_text: str) -> None:
        self.write(mr.markdown(md_text))

    def add_result(self, result: dict) -> None:
        if result.get("type") == "clear":
            self.clear()
            return
        self.write(mr.render_result(result))
