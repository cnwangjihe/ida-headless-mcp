"""idalib Pool Proxy — MCP server that manages a pool of idalib instances.

This process does NOT import ``idapro``.  It speaks MCP over HTTP to clients
and forwards IDA tool calls to backend idalib_server sub-processes connected
via Unix domain sockets.

Each MCP transport session (SSE connection or Streamable HTTP session) gets
its own context binding, so multiple agents sharing one endpoint can work on
different IDBs without interfering.  Sessions are reference-counted: when the
last agent closes its reference, the IDB is saved and the instance is killed.

Usage::

    uv run idalib-pool --port 8750 /path/to/binary          # single binary
    uv run idalib-pool --max-instances 3 --port 8750         # pre-warm 3 instances
"""

from __future__ import annotations

import argparse
import copy
import json
import logging
import os
import signal
import sys
import time
import traceback
from pathlib import Path
from typing import Any

# Import zeromcp directly from the vendored package path without triggering
# ida_mcp/__init__.py (which imports idapro-dependent modules).
import importlib.util

def _import_zeromcp_module(name: str, subpath: str):
    """Import a zeromcp module by file path, bypassing ida_mcp.__init__."""
    zeromcp_dir = os.path.join(os.path.dirname(__file__), "ida_mcp", "zeromcp")
    spec = importlib.util.spec_from_file_location(name, os.path.join(zeromcp_dir, subpath))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod

_jsonrpc_mod = _import_zeromcp_module(
    "ida_pro_mcp.ida_mcp.zeromcp.jsonrpc", "jsonrpc.py"
)
_mcp_mod = _import_zeromcp_module(
    "ida_pro_mcp.ida_mcp.zeromcp.mcp", "mcp.py"
)
McpServer = _mcp_mod.McpServer
JsonRpcResponse = _jsonrpc_mod.JsonRpcResponse

from ida_pro_mcp.idalib_pool_manager import PoolManager  # noqa: E402

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------
# Management tool names that the proxy intercepts
# --------------------------------------------------------------------------

IDALIB_MANAGEMENT_TOOLS = {
    "idalib_open",
    "idalib_close",
    "idalib_switch",
    "idalib_list",
    "idalib_current",
    "idalib_save",
    "idalib_health",
    "idalib_warmup",
}

# Backend tools that are not exposed in pool mode
_HIDDEN_BACKEND_TOOLS = {"idalib_unbind"}

# --------------------------------------------------------------------------
# Tool schema injection
# --------------------------------------------------------------------------

_SESSION_ID_SCHEMA: dict = {
    "type": "string",
    "description": (
        "Session ID to route this call to. "
        "If omitted, routes to the session bound to the caller's context."
    ),
}

# Management tool schemas — override backend descriptions for pool semantics.
_MGMT_TOOL_OVERRIDES: dict[str, dict] = {
    "idalib_open": {
        "name": "idalib_open",
        "description": (
            "Open a binary for analysis. If the binary is already open by "
            "another agent, shares the existing session. The returned "
            "session_id may differ from the one you requested — always use "
            "the returned session_id for subsequent calls. Each idalib_open "
            "must be balanced by an idalib_close when you are done."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "input_path": {
                    "type": "string",
                    "description": "Path to the binary file to analyze",
                },
                "run_auto_analysis": {
                    "type": "boolean",
                    "description": "Run automatic analysis on the binary (default: true)",
                },
                "session_id": {
                    "type": "string",
                    "description": (
                        "Suggested session ID. This is advisory only — if the "
                        "binary is already open, the existing session_id is "
                        "returned instead."
                    ),
                },
            },
            "required": ["input_path"],
        },
    },
    "idalib_close": {
        "name": "idalib_close",
        "description": (
            "Release your reference to a session. The IDB is only closed "
            "when all agents have released their references (refcount "
            "reaches zero). Defaults to your currently bound session."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": (
                        "Session ID to close. If omitted, closes the session "
                        "bound to your context."
                    ),
                },
                "force": {
                    "type": "boolean",
                    "description": (
                        "Force-close the session regardless of refcount. "
                        "DANGEROUS: disconnects all other agents using this "
                        "session. Only use when you need to immediately save "
                        "and release the IDB."
                    ),
                },
            },
        },
    },
    "idalib_switch": {
        "name": "idalib_switch",
        "description": (
            "Switch your default session routing to a different existing "
            "session. This does not affect reference counts — you still need "
            "to idalib_close sessions you opened. Use this to access a "
            "session opened by another agent without changing ownership."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Session ID to route your requests to",
                },
            },
            "required": ["session_id"],
        },
    },
    "idalib_list": {
        "name": "idalib_list",
        "description": (
            "List all open sessions with refcounts. Shows which session is "
            "bound to your context."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    "idalib_current": {
        "name": "idalib_current",
        "description": (
            "Return the session currently bound to your context, or an error "
            "if no session is bound."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    "idalib_save": {
        "name": "idalib_save",
        "description": (
            "Save the IDB to disk without closing the session. Defaults to "
            "your currently bound session."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Destination path (default: current IDB path)",
                },
                "session_id": {
                    "type": "string",
                    "description": (
                        "Session to save. If omitted, saves the session "
                        "bound to your context."
                    ),
                },
            },
        },
    },
    "idalib_health": {
        "name": "idalib_health",
        "description": (
            "Health/ready probe. Defaults to your currently bound session."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": (
                        "Session to probe. If omitted, probes the session "
                        "bound to your context."
                    ),
                },
            },
        },
    },
    "idalib_warmup": {
        "name": "idalib_warmup",
        "description": (
            "Warm up subsystems (Hex-Rays, caches). Defaults to your "
            "currently bound session."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": (
                        "Session to warm up. If omitted, warms the session "
                        "bound to your context."
                    ),
                },
                "wait_auto_analysis": {
                    "type": "boolean",
                    "description": "Wait for auto analysis queue (default: true)",
                },
                "build_caches": {
                    "type": "boolean",
                    "description": "Build core caches (default: true)",
                },
                "init_hexrays": {
                    "type": "boolean",
                    "description": "Initialize Hex-Rays plugin (default: true)",
                },
            },
        },
    },
}


def _prepare_tools(tools: list[dict]) -> list[dict]:
    """Prepare tool schemas for the proxy.

    Management tools are replaced with pool-specific schemas that describe
    the refcount/routing semantics.  Backend-only tools (idalib_unbind) are
    hidden.  All other IDA tools get an optional ``session_id`` parameter
    injected so clients can route per-tool.
    """
    seen_mgmt: set[str] = set()
    result = []
    for tool in tools:
        name = tool.get("name", "")
        if name in _HIDDEN_BACKEND_TOOLS:
            continue
        if name in _MGMT_TOOL_OVERRIDES:
            if name not in seen_mgmt:
                result.append(copy.deepcopy(_MGMT_TOOL_OVERRIDES[name]))
                seen_mgmt.add(name)
            continue
        tool = copy.deepcopy(tool)
        if name not in IDALIB_MANAGEMENT_TOOLS:
            schema = tool.setdefault("inputSchema", {})
            props = schema.setdefault("properties", {})
            if "session_id" not in props:
                props["session_id"] = _SESSION_ID_SCHEMA
        result.append(tool)
    return result


# --------------------------------------------------------------------------
# Proxy dispatch
# --------------------------------------------------------------------------

def build_dispatch(mcp: McpServer, pool: PoolManager):
    """Patch ``mcp.registry.dispatch`` with pool-aware routing."""

    dispatch_original = mcp.registry.dispatch
    _tools_cache: list[dict] | None = None

    def _ensure_tools_cache() -> list[dict]:
        nonlocal _tools_cache
        if _tools_cache is None:
            raw = pool.forward_tools_list()
            _tools_cache = _prepare_tools(raw)
        return _tools_cache

    def _get_transport_ctx() -> str | None:
        return mcp.get_current_transport_session_id()

    def _resolve_session_id(arguments: dict) -> str:
        """2-tier session resolution: explicit arg > context binding."""
        sid = arguments.pop("session_id", None)
        if sid:
            return sid
        ctx = _get_transport_ctx()
        if ctx:
            sid = pool.get_context_session_id(ctx)
        if sid:
            return sid
        raise KeyError("No session bound. Use idalib_open to create a session first.")

    def _error_response(request_id: Any, code: int, message: str) -> JsonRpcResponse:
        if request_id is None:
            return None  # type: ignore[return-value]
        return {
            "jsonrpc": "2.0",
            "error": {"code": code, "message": message},
            "id": request_id,
        }

    # --- Management tool handlers ---

    def _handle_idalib_open(arguments: dict) -> dict:
        input_path = arguments.get("input_path", "")
        session_id = arguments.get("session_id")
        run_auto = arguments.get("run_auto_analysis", True)

        result = pool.open_session(input_path, session_id=session_id, run_auto_analysis=run_auto)
        if not result.get("success"):
            return result

        actual_sid = result["session"]["session_id"]
        ctx = _get_transport_ctx()
        if ctx:
            pool.bind_context(ctx, actual_sid)
            pool.increment_refcount(actual_sid)

        result["session"]["refcount"] = pool.get_refcount(actual_sid)
        return result

    def _handle_idalib_close(arguments: dict) -> dict:
        force = arguments.get("force", False)

        sid = arguments.get("session_id")
        ctx = _get_transport_ctx()
        if not sid and ctx:
            sid = pool.get_context_session_id(ctx)
        if not sid:
            return {"success": False, "error": "No session bound. Use idalib_open first."}

        if ctx:
            bound_sid = pool.get_context_session_id(ctx)
            if bound_sid == sid:
                pool.unbind_context(ctx)

        if force:
            with pool._lock:
                pool.sr._unbind_session_everywhere(sid)
            result = pool.close_session(sid)
            result["closed"] = True
            return result

        new_rc = pool.decrement_refcount(sid)
        if new_rc <= 0:
            result = pool.close_session(sid)
            result["closed"] = True
            return result

        return {
            "success": True,
            "closed": False,
            "refcount": new_rc,
            "message": f"Reference released. Session '{sid}' still has {new_rc} reference(s).",
        }

    def _handle_idalib_switch(arguments: dict) -> dict:
        sid = arguments.get("session_id", "")
        ctx = _get_transport_ctx()
        if not ctx:
            return {"success": False, "error": "No transport context available."}

        with pool._lock:
            sess = pool.sr.get(sid)
            if sess is None:
                return {"success": False, "error": f"Session not found: {sid}"}
            pool.sr.bind_context(ctx, sid)
            sess.last_accessed = time.monotonic()
            return {
                "success": True,
                "session": sess.to_dict(refcount=pool.sr.get_refcount(sid)),
                "message": f"Context now routes to session: {sid}",
            }

    def _handle_idalib_list(_arguments: dict) -> dict:
        ctx = _get_transport_ctx()
        return pool.list_sessions(context_id=ctx)

    def _handle_idalib_current(_arguments: dict) -> dict:
        ctx = _get_transport_ctx()
        if not ctx:
            return {"error": "No transport context available."}
        sid = pool.get_context_session_id(ctx)
        if not sid:
            return {"error": "No session bound. Use idalib_open first."}
        with pool._lock:
            sess = pool.sr.get(sid)
            if sess is None:
                return {"error": f"Bound session '{sid}' no longer exists."}
            return sess.to_dict(refcount=pool.sr.get_refcount(sid))

    def _handle_idalib_save(arguments: dict) -> dict:
        sid = arguments.pop("session_id", None)
        ctx = _get_transport_ctx()
        if not sid and ctx:
            sid = pool.get_context_session_id(ctx)
        if not sid:
            return {"error": "No session to save. Use idalib_open first."}
        try:
            _sess, inst = pool.resolve_session_instance(sid)
        except (KeyError, RuntimeError) as e:
            return {"error": str(e)}
        return pool.forward_tool_call(inst, "idalib_save", arguments)

    def _handle_idalib_health(arguments: dict) -> dict:
        sid = arguments.pop("session_id", None)
        ctx = _get_transport_ctx()
        if not sid and ctx:
            sid = pool.get_context_session_id(ctx)
        if not sid:
            return {"ready": False, "error": "No session bound. Use idalib_open first."}
        try:
            _sess, inst = pool.resolve_session_instance(sid)
        except (KeyError, RuntimeError) as e:
            return {"ready": False, "error": str(e)}
        return pool.forward_tool_call(inst, "idalib_health", arguments)

    def _handle_idalib_warmup(arguments: dict) -> dict:
        sid = arguments.pop("session_id", None)
        ctx = _get_transport_ctx()
        if not sid and ctx:
            sid = pool.get_context_session_id(ctx)
        if not sid:
            return {"ready": False, "error": "No session bound. Use idalib_open first."}
        try:
            _sess, inst = pool.resolve_session_instance(sid)
        except (KeyError, RuntimeError) as e:
            return {"ready": False, "error": str(e)}
        return pool.forward_tool_call(inst, "idalib_warmup", arguments)

    _mgmt_handlers: dict[str, Any] = {
        "idalib_open": _handle_idalib_open,
        "idalib_close": _handle_idalib_close,
        "idalib_switch": _handle_idalib_switch,
        "idalib_list": _handle_idalib_list,
        "idalib_current": _handle_idalib_current,
        "idalib_save": _handle_idalib_save,
        "idalib_health": _handle_idalib_health,
        "idalib_warmup": _handle_idalib_warmup,
    }

    # --- tools/call handler ---

    def _handle_tools_call(request_obj: dict) -> JsonRpcResponse | None:
        params = request_obj.get("params", {})
        tool_name = params.get("name", "")
        arguments = params.get("arguments") or {}
        request_id = request_obj.get("id")

        # 1. Management tools — handle locally
        handler = _mgmt_handlers.get(tool_name)
        if handler is not None:
            try:
                result = handler(dict(arguments))
            except Exception as e:
                return _error_response(request_id, -32000, str(e))
            return {
                "jsonrpc": "2.0",
                "result": {
                    "content": [{"type": "text", "text": json.dumps(result, indent=2)}],
                    "structuredContent": result if isinstance(result, dict) else {"result": result},
                    "isError": bool(isinstance(result, dict) and result.get("error")),
                },
                "id": request_id,
            }

        # 2. IDA tools — route via 2-tier resolution
        try:
            session_id = _resolve_session_id(dict(arguments))
        except KeyError as e:
            return _error_response(request_id, -32001, str(e))

        try:
            _sess, inst = pool.resolve_session_instance(session_id)
        except (KeyError, RuntimeError) as e:
            return _error_response(request_id, -32001, str(e))

        forwarded = copy.deepcopy(request_obj)
        fwd_args = forwarded.get("params", {}).get("arguments", {})
        fwd_args.pop("session_id", None)

        return pool.forward_raw(inst, forwarded)

    # --- tools/list handler ---

    def _handle_tools_list(request_obj: dict) -> JsonRpcResponse:
        return {
            "jsonrpc": "2.0",
            "result": {"tools": _ensure_tools_cache()},
            "id": request_obj.get("id"),
        }

    # --- Main dispatch ---

    def dispatch_proxy(request: dict | str | bytes | bytearray) -> JsonRpcResponse | None:
        if not isinstance(request, dict):
            request_obj: dict = json.loads(request)
        else:
            request_obj = request

        method = request_obj.get("method", "")
        request_id = request_obj.get("id")

        if method == "initialize":
            return dispatch_original(request)
        if method.startswith("notifications/"):
            return dispatch_original(request)

        if method == "tools/list":
            return _handle_tools_list(request_obj)

        if method == "tools/call":
            try:
                return _handle_tools_call(request_obj)
            except Exception as e:
                tb = traceback.format_exc()
                return _error_response(request_id, -32000, f"{e}\n{tb}")

        # Everything else (resources, etc.) — route via context binding
        ctx = _get_transport_ctx()
        sid = pool.get_context_session_id(ctx) if ctx else None
        if sid is None:
            return _error_response(
                request_id, -32001,
                f"No session bound for method '{method}'. Use idalib_open first.",
            )
        try:
            _sess, inst = pool.resolve_session_instance(sid)
        except (KeyError, RuntimeError) as e:
            return _error_response(request_id, -32001, str(e))
        return pool.forward_raw(inst, request_obj)

    mcp.registry.dispatch = dispatch_proxy


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="MCP proxy server managing a pool of idalib instances"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Show debug messages"
    )
    parser.add_argument(
        "--transport", type=str, default="stdio",
        help="Transport: 'stdio' (default) or a URL (e.g. http://127.0.0.1:8750)",
    )
    parser.add_argument(
        "--max-instances", type=int, default=1,
        help="Number of idalib instances to pre-warm (default: 1). "
             "Additional instances are spawned on demand as needed.",
    )
    parser.add_argument(
        "--socket-dir", type=str, default=None,
        help="Directory for instance Unix sockets (default: auto temp dir)",
    )
    parser.add_argument(
        "--unsafe", action="store_true",
        help="Pass --unsafe to idalib instances",
    )
    parser.add_argument(
        "--auth-token", type=str,
        default=os.environ.get("IDA_MCP_AUTH_TOKEN"),
        help="Bearer token for HTTP authentication (or set IDA_MCP_AUTH_TOKEN)",
    )
    parser.add_argument(
        "input_path", type=Path, nargs="?",
        help="Optional binary to open on startup.",
    )
    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level)

    idalib_args: list[str] = []
    if args.verbose:
        idalib_args.append("--verbose")
    if args.unsafe:
        idalib_args.append("--unsafe")

    pool = PoolManager(
        max_instances=args.max_instances,
        socket_dir=args.socket_dir,
        idalib_args=idalib_args,
    )

    mcp = McpServer("ida-pro-mcp")
    mcp.require_streamable_http_session = True
    if args.auth_token:
        mcp.auth_token = args.auth_token

    logger.info("Spawning initial instance for tool discovery...")
    pool.spawn_instance()

    build_dispatch(mcp, pool)

    if args.input_path is not None:
        if not args.input_path.exists():
            print(f"Error: Input file not found: {args.input_path}", file=sys.stderr)
            sys.exit(1)
        logger.info("Opening initial binary: %s", args.input_path)
        result = pool.open_session(str(args.input_path))
        if isinstance(result, dict) and result.get("error"):
            print(f"Error opening binary: {result['error']}", file=sys.stderr)
            sys.exit(1)
        sid = result.get("session", {}).get("session_id")
        logger.info("Initial session: %s (no context binding — use idalib_open from a client)", sid)

    def cleanup(signum, frame):
        logger.info("Shutting down pool...")
        pool.shutdown_all()
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    transport = args.transport
    if transport == "stdio":
        mcp.stdio()
    else:
        from urllib.parse import urlparse
        url = urlparse(transport)
        if not url.hostname or not url.port:
            print(f"Error: invalid transport URL: {transport}", file=sys.stderr)
            sys.exit(1)
        mcp.serve(host=url.hostname, port=url.port, background=False)


if __name__ == "__main__":
    main()
