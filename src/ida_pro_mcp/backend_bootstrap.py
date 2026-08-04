"""Minimal spawn target for an idalib backend process.

This module intentionally avoids importing idapro or the MCP tool registry.
The spawned interpreter redirects its output first, then imports the heavy
backend module so native and Python diagnostics cannot corrupt pool stdio.
"""

from __future__ import annotations

import importlib
import logging
import os
import sys

from ida_pro_mcp.backend_ipc import make_message, send_message
from ida_pro_mcp.logging_config import (
    configure_runtime_logging,
    log_level_from_args,
)


logger = logging.getLogger("ida_mcp.backend.bootstrap")


def _redirect_output(log_path: str):
    log_file = open(
        log_path,
        "w",
        encoding="utf-8",
        errors="backslashreplace",
        buffering=1,
    )
    try:
        os.dup2(log_file.fileno(), 1)
        os.dup2(log_file.fileno(), 2)
    except OSError:
        # Rebinding the Python streams still protects stdio transports on
        # hosts where a standard CRT file descriptor is unavailable.
        pass
    sys.stdout = log_file
    sys.stderr = log_file
    return log_file


def run_backend_process(
    rpc_connection,
    control_connection,
    log_path: str,
    idalib_args: list[str],
) -> None:
    """Spawn entry point used by ``multiprocessing.Process``."""
    log_file = _redirect_output(log_path)
    configure_runtime_logging(log_level_from_args(idalib_args))
    try:
        idalib_server = importlib.import_module("ida_pro_mcp.idalib_server")

        idalib_server.run_ipc_backend(
            rpc_connection,
            control_connection,
            idalib_args=idalib_args,
        )
    except BaseException as e:
        try:
            send_message(
                rpc_connection,
                make_message("startup_error", error=str(e)),
            )
        except Exception:
            pass
        logger.exception("IDA backend process failed during startup or execution")
        raise
    finally:
        rpc_connection.close()
        control_connection.close()
        try:
            log_file.flush()
        except (OSError, ValueError):
            pass
