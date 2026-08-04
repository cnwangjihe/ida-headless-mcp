"""idalib backend — single-IDB headless MCP server.

This process is spawned by the pool manager.  It opens at most one IDB
at a time and serves IDA MCP tools over inherited multiprocessing pipes.
Multi-session orchestration lives in the pool layer; this backend is
intentionally simple.
"""

import logging
import os
from typing import Annotated, Optional

import idapro
import ida_auto
import ida_loader
import ida_nalt

from ida_pro_mcp.ida_mcp import MCP_SERVER, MCP_UNSAFE
from ida_pro_mcp.ida_mcp.api_core import server_health, server_warmup
from ida_pro_mcp.ida_mcp.rpc import tool
from ida_pro_mcp.ida_mcp.zeromcp.jsonrpc import cancel_all_pending_requests
from ida_pro_mcp.ida_mcp.zeromcp.mcp import LATEST_MCP_PROTOCOL_VERSION
from ida_pro_mcp.backend_ipc import BackendIpcServer
from ida_pro_mcp.logging_config import (
    configure_runtime_logging,
    normalize_log_level,
)

logger = logging.getLogger("ida_mcp.backend")

_current_session_id: str | None = None
_current_input_path: str = ""
_current_idb_path: str = ""


def _open_database(input_path: str, run_auto_analysis: bool = True) -> None:
    """Open the only database owned by this backend."""
    global _current_input_path, _current_idb_path

    if _current_session_id is not None:
        raise RuntimeError(
            f"Backend already owns session {_current_session_id}; "
            "start a new backend for another database"
        )

    if idapro.open_database(input_path, run_auto_analysis=run_auto_analysis):
        raise RuntimeError(f"Failed to open database: {input_path}")

    if run_auto_analysis:
        ida_auto.auto_wait()

    _current_input_path = ida_nalt.get_input_file_path() or input_path
    _current_idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB) or ""


def _session_dict() -> dict:
    return {
        "session_id": _current_session_id or "",
        "input_path": _current_input_path,
        "idb_path": _current_idb_path,
        "filename": os.path.basename(_current_input_path),
    }


# ---------------------------------------------------------------------------
# Management tools (called by pool proxy via JSON-RPC forwarding)
# ---------------------------------------------------------------------------

@tool
def idalib_open(
    input_path: Annotated[str, "Path to the binary or IDB to analyze"],
    run_auto_analysis: Annotated[bool, "Run automatic analysis"] = True,
    session_id: Annotated[Optional[str], "Session ID assigned by pool"] = None,
) -> dict:
    """Open a binary in this idalib instance."""
    global _current_session_id
    try:
        _open_database(input_path, run_auto_analysis)
        _current_session_id = session_id
        return {"success": True, "session": _session_dict()}
    except Exception as e:
        return {"error": str(e)}


@tool
def idalib_close(
    session_id: Annotated[str, "Session ID to close"],
) -> dict:
    """Close the current database."""
    global _current_session_id, _current_input_path, _current_idb_path
    try:
        if _current_session_id is not None:
            idapro.close_database()
        _current_session_id = None
        _current_input_path = ""
        _current_idb_path = ""
        return {"success": True, "message": f"Session closed: {session_id}"}
    except Exception as e:
        return {"error": f"Failed to close session: {e}"}


@tool
def idalib_health() -> dict:
    """Health/ready probe."""
    try:
        health = server_health()
        return {
            "ready": bool(health.get("status") == "ok"),
            "session": _session_dict() if _current_session_id else None,
            "health": health,
        }
    except Exception as e:
        return {"ready": False, "error": str(e)}


@tool
def idalib_warmup(
    wait_auto_analysis: Annotated[bool, "Wait for auto analysis queue"] = True,
    build_caches: Annotated[bool, "Build core caches"] = True,
    init_hexrays: Annotated[bool, "Initialize Hex-Rays plugin"] = True,
) -> dict:
    """Warm up subsystems (Hex-Rays, caches)."""
    try:
        warmup = server_warmup(
            wait_auto_analysis=wait_auto_analysis,
            build_caches=build_caches,
            init_hexrays=init_hexrays,
        )
        return {
            "ready": bool(warmup.get("ok")),
            "session": _session_dict() if _current_session_id else None,
            "warmup": warmup,
        }
    except Exception as e:
        return {"ready": False, "error": str(e)}


def _close_current_database() -> None:
    global _current_session_id, _current_input_path, _current_idb_path
    if _current_session_id is not None:
        try:
            idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
            if idb_path:
                ida_loader.save_database(idb_path, 0)
        except Exception as e:
            logger.warning("Failed to save on shutdown: %s", e)
        idapro.close_database()
        _current_session_id = None
        _current_input_path = ""
        _current_idb_path = ""


def _dispatch_ipc_request(request: dict) -> dict | None:
    setattr(MCP_SERVER._enabled_extensions, "data", set())
    setattr(MCP_SERVER._protocol_version, "data", LATEST_MCP_PROTOCOL_VERSION)
    setattr(MCP_SERVER._transport_session_id, "data", "backend:default")
    try:
        return MCP_SERVER.registry.dispatch(request)
    finally:
        setattr(MCP_SERVER._enabled_extensions, "data", set())
        setattr(MCP_SERVER._protocol_version, "data", None)
        setattr(MCP_SERVER._transport_session_id, "data", None)


def run_ipc_backend(
    rpc_connection,
    control_connection,
    *,
    idalib_args: list[str],
) -> None:
    """Run the single-IDB backend over inherited multiprocessing pipes."""
    log_level = "info"
    safe = False
    index = 0
    while index < len(idalib_args):
        argument = idalib_args[index]
        if argument == "--log-level":
            index += 1
            if index >= len(idalib_args):
                raise ValueError("--log-level requires a value")
            log_level = normalize_log_level(idalib_args[index])
        elif argument.startswith("--log-level="):
            log_level = normalize_log_level(argument.split("=", 1)[1])
        elif argument == "--safe":
            safe = True
        elif argument == "--unsafe":
            safe = False
        else:
            raise ValueError(f"Unsupported backend argument: {argument}")
        index += 1

    configure_runtime_logging(log_level)
    idapro.enable_console_messages(log_level == "debug")
    if safe:
        MCP_SERVER.disabled_tools.update(MCP_UNSAFE)

    server = BackendIpcServer(
        rpc_connection,
        control_connection,
        dispatch=_dispatch_ipc_request,
        cancel_pending=cancel_all_pending_requests,
    )
    try:
        server.serve(ready_fields={"pid": os.getpid()})
    finally:
        logger.info("Shutting down...")
        _close_current_database()
