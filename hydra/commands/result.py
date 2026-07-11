"""CommandResult — the universal return type from command execution."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class CommandResult:
    status: str = "success"
    output: Any = None
    events: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status == "success"

    @staticmethod
    def success(output: Any = None, **kwargs) -> "CommandResult":
        return CommandResult(status="success", output=output, **kwargs)

    @staticmethod
    def error(message: str, **kwargs) -> "CommandResult":
        return CommandResult(status="error", errors=[message], **kwargs)

    @staticmethod
    def pending(output: Any = None, **kwargs) -> "CommandResult":
        return CommandResult(status="pending", output=output, **kwargs)
