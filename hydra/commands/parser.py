"""Command parser — splits raw user input into structured parts."""

import shlex
from dataclasses import dataclass, field


@dataclass
class ParsedCommand:
    name: str
    args: list[str] = field(default_factory=list)
    kwargs: dict[str, str] = field(default_factory=dict)
    raw: str = ""


def parse_command(raw: str) -> ParsedCommand | None:
    raw = raw.strip()
    if not raw:
        return None

    if not raw.startswith("/"):
        return ParsedCommand(name="chat", args=[raw], raw=raw)

    try:
        tokens = shlex.split(raw)
    except ValueError:
        tokens = raw.split()

    name = tokens[0].lstrip("/")
    args = []
    kwargs = {}

    for token in tokens[1:]:
        if token.startswith("--") and "=" in token:
            key, _, val = token[2:].partition("=")
            kwargs[key] = val
        elif token.startswith("--"):
            kwargs[token[2:]] = "true"
        else:
            args.append(token)

    return ParsedCommand(name=name, args=args, kwargs=kwargs, raw=raw)
