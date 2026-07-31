"""idalib backend — single-IDB headless MCP server.

This process is spawned by the pool manager.  It opens at most one IDB
at a time and exposes IDA MCP tools over an HTTP Unix socket.
Multi-session orchestration lives in the pool layer; this backend is
intentionally simple.
"""

import argparse
import logging
import os
import signal
from typing import Annotated, Optional

import idapro
import ida_auto
import ida_loader
import ida_nalt

from ida_pro_mcp.ida_mcp import MCP_SERVER, MCP_UNSAFE
from ida_pro_mcp.ida_mcp.api_core import server_health, server_warmup
from ida_pro_mcp.ida_mcp.rpc import tool
from ida_pro_mcp.ida_mcp.zeromcp.jsonrpc import cancel_all_pending_requests

logger = logging.getLogger(__name__)

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
def idalib_save(
    path: Annotated[str, "Destination path (default: current IDB path)"] = "",
) -> dict:
    """Save the current database to disk."""
    try:
        save_path = path.strip() if path else ""
        if not save_path:
            save_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        if not save_path:
            return {"ok": False, "error": "Could not resolve IDB path"}
        ok = bool(ida_loader.save_database(save_path, 0))
        return {"ok": ok, "path": save_path, "error": None if ok else "save failed"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


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


# These tools exist so the pool can discover them via tools/list,
# but the pool proxy intercepts them and never forwards them.

@tool
def idalib_switch(
    session_id: Annotated[str, "Session ID"],
) -> dict:
    """Switch session (handled by pool proxy)."""
    return {"error": "idalib_switch is handled by the pool proxy, not the backend."}


@tool
def idalib_list() -> dict:
    """List sessions (handled by pool proxy)."""
    return {"sessions": [_session_dict()] if _current_session_id else [], "count": 1 if _current_session_id else 0}


@tool
def idalib_current() -> dict:
    """Return current session info."""
    if _current_session_id is None:
        return {"error": "No session open."}
    return _session_dict()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="idalib backend — single-IDB headless MCP server"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Show debug messages"
    )
    safety = parser.add_mutually_exclusive_group()
    safety.add_argument(
        "--safe", action="store_true",
        help="Disable tools marked as unsafe (unsafe tools are enabled by default)",
    )
    safety.add_argument(
        "--unsafe", dest="safe", action="store_false", help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--unix-socket", type=str, required=True,
        help="Unix domain socket used by the pool manager",
    )
    args = parser.parse_args()

    if args.verbose:
        log_level = logging.DEBUG
        idapro.enable_console_messages(True)
    else:
        log_level = logging.INFO
        idapro.enable_console_messages(False)

    logging.basicConfig(level=log_level)

    if args.safe:
        MCP_SERVER.disabled_tools.update(MCP_UNSAFE)

    def close_current_database() -> None:
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

    def request_shutdown(signum, frame):
        logger.info("Shutdown requested")
        raise SystemExit(0)

    signal.signal(signal.SIGINT, request_shutdown)
    signal.signal(signal.SIGTERM, request_shutdown)
    if hasattr(signal, "SIGUSR1"):
        def request_cancel(signum, frame):
            cancelled = cancel_all_pending_requests()
            logger.info("Cancellation requested for %d active call(s)", cancelled)

        signal.signal(signal.SIGUSR1, request_cancel)

    try:
        MCP_SERVER.serve(unix_socket=args.unix_socket, background=False)
    finally:
        logger.info("Shutting down...")
        close_current_database()


if __name__ == "__main__":
    main()
