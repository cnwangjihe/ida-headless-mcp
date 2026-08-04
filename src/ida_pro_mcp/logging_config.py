"""Shared runtime logging configuration for CLI and backend processes."""

from __future__ import annotations

import logging
import sys
from typing import TextIO


LOGGER_NAMESPACE = "ida_mcp"
LOG_LEVEL_NAMES = ("debug", "info", "warning", "error", "critical")
LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
_HANDLER_MARKER = "_ida_mcp_runtime_handler"


def normalize_log_level(level: str) -> str:
    normalized = level.strip().lower()
    if normalized not in LOG_LEVEL_NAMES:
        raise ValueError(
            f"Unsupported log level {level!r}; expected one of "
            f"{', '.join(LOG_LEVEL_NAMES)}"
        )
    return normalized


def log_level_from_args(arguments: list[str], default: str = "info") -> str:
    """Read an internal ``--log-level`` argument without consuming argv."""
    for index, argument in enumerate(arguments):
        if argument.startswith("--log-level="):
            return argument.split("=", 1)[1]
        if argument == "--log-level" and index + 1 < len(arguments):
            return arguments[index + 1]
    return default


def configure_runtime_logging(
    level: str,
    *,
    stream: TextIO | None = None,
) -> logging.Logger:
    """Configure the project logger hierarchy without changing the root logger."""
    normalized = normalize_log_level(level)
    namespace_logger = logging.getLogger(LOGGER_NAMESPACE)
    output = stream if stream is not None else sys.stderr

    handler = next(
        (
            candidate
            for candidate in namespace_logger.handlers
            if getattr(candidate, _HANDLER_MARKER, False)
        ),
        None,
    )
    if handler is None:
        handler = logging.StreamHandler(output)
        setattr(handler, _HANDLER_MARKER, True)
        namespace_logger.addHandler(handler)
    else:
        handler.setStream(output)

    handler.setLevel(logging.NOTSET)
    handler.setFormatter(logging.Formatter(LOG_FORMAT, LOG_DATE_FORMAT))
    namespace_logger.setLevel(getattr(logging, normalized.upper()))
    namespace_logger.propagate = False
    return namespace_logger
