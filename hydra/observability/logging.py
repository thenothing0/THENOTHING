"""Structured logging with correlation IDs and optional JSON output."""

from __future__ import annotations

import contextvars
import json
import logging
import time
import uuid
from typing import Any

_correlation_id: contextvars.ContextVar[str] = contextvars.ContextVar(
    "correlation_id", default=""
)


def set_correlation_id(cid: str | None = None) -> str:
    """Set the correlation ID for the current context. Generates one if not provided."""
    cid = cid or uuid.uuid4().hex[:12]
    _correlation_id.set(cid)
    return cid


def get_correlation_id() -> str:
    """Return the current correlation ID (empty string if unset)."""
    return _correlation_id.get()


class CorrelationFilter(logging.Filter):
    """Injects ``correlation_id`` into every log record from a ContextVar."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.correlation_id = _correlation_id.get()  # type: ignore[attr-defined]
        return True


class JSONFormatter(logging.Formatter):
    """Structured JSON log formatter.

    Each line is a self-contained JSON object with:
    timestamp, level, logger, message, correlation_id, filename, function, line.
    """

    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "timestamp": time.strftime(
                "%Y-%m-%dT%H:%M:%S", time.localtime(record.created)
            )
            + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "correlation_id": getattr(record, "correlation_id", ""),
            "filename": record.filename,
            "function": record.funcName,
            "line": record.lineno,
        }
        if record.exc_info and record.exc_info[1] is not None:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str)


def configure_logging(
    json_output: bool = False,
    level: str = "INFO",
) -> None:
    """Install the CorrelationFilter on the root logger.

    Optionally swap the formatter of all existing handlers to JSONFormatter.
    This is backward compatible: when ``json_output`` is False, existing
    formatters are untouched and only the filter is added.
    """
    root = logging.getLogger()
    filt = CorrelationFilter()

    for handler in root.handlers:
        handler.addFilter(filt)
        if json_output:
            handler.setFormatter(JSONFormatter())

    root.addFilter(filt)

    num_level = getattr(logging, level.upper(), logging.INFO)
    if root.level > num_level:
        root.setLevel(num_level)
