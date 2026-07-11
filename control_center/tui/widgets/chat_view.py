"""ChatView — the primary, chat-first conversation surface.

A ``RichLog`` (line-virtualised, bounded by ``max_lines``) styled like Claude
Code: user turns as bubbles, results as quiet panels, markdown / syntax / tables
in the body, and live line-by-line streaming of AI tokens and tool output.

It carries no business logic: the App feeds it via these methods (from event
handlers / workers); all rendering is delegated to ``markdown_renderer``.
"""

from __future__ import annotations

from textual.widgets import RichLog

from control_center.tui.widgets import markdown_renderer as mr

MAX_LINES = 50_000


class ChatView(RichLog):
    """Scrollable, virtualised conversation log (the dominant widget)."""

    DEFAULT_CSS = """
    ChatView {
        height: 1fr;
        padding: 0 1;
        background: $surface;
        scrollbar-size: 1 1;
    }
    """

    def __init__(self, **kwargs) -> None:
        kwargs.setdefault("max_lines", MAX_LINES)
        kwargs.setdefault("wrap", True)
        kwargs.setdefault("auto_scroll", True)
        super().__init__(**kwargs)
        self._stream_buf = ""

    def on_mount(self) -> None:
        self.write(mr.banner())

    # ── Discrete messages (same API as ConversationLog) ──

    def add_user_input(self, text: str) -> None:
        self._flush_stream()
        self.write(mr.user_message(text))

    def add_system(self, text: str) -> None:
        self._flush_stream()
        self.write(mr.system_message(text))

    def add_error(self, text: str) -> None:
        self._flush_stream()
        self.write(mr.error_message(text))

    def add_markdown(self, md_text: str) -> None:
        self._flush_stream()
        self.write(mr.markdown(md_text))

    def add_result(self, result: dict) -> None:
        self._flush_stream()
        if result.get("type") == "clear":
            self.clear()
            return
        self.write(mr.render_result(result))

    def add_assistant(self, body, title: str = "hydra") -> None:
        self._flush_stream()
        self.write(mr.assistant_message(body, title=title))

    # ── Live streaming (AI tokens / tool output) ──

    def stream_token(self, token: str) -> None:
        """Append an AI token; emit completed lines as they form."""
        self._stream_buf += token
        while "\n" in self._stream_buf:
            line, self._stream_buf = self._stream_buf.split("\n", 1)
            self.write(mr.markdown(line) if line.strip() else "")

    def stream_chunk(self, text: str) -> None:
        """Append a tool-output chunk as dim, line-buffered text."""
        self._stream_buf += text
        while "\n" in self._stream_buf:
            line, self._stream_buf = self._stream_buf.split("\n", 1)
            self.write(mr.system_message(line))

    def end_stream(self) -> None:
        self._flush_stream()

    def _flush_stream(self) -> None:
        if self._stream_buf:
            self.write(mr.system_message(self._stream_buf))
            self._stream_buf = ""
