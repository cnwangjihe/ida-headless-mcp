"""idalib Pool Proxy — MCP server that manages a pool of idalib instances.

This process does NOT import ``idapro``.  It speaks MCP over stdio, Streamable
HTTP, or SSE and forwards IDA tool calls to spawned backend processes through
inherited multiprocessing pipes.

Each MCP transport session (SSE connection or Streamable HTTP session) gets
its own context binding, so multiple agents sharing one endpoint can work on
different IDBs without interfering.  Sessions are reference-counted: when the
last agent closes its reference, the IDB is saved and the instance is killed.

Usage::

    uv run idalib-pool
    uv run idalib-pool --transport http://127.0.0.1:8750
"""

from __future__ import annotations

import argparse
import copy
import json
import logging
import os
import re
import secrets
import signal
import sys
import threading
import time
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
McpHttpRequestHandler = _mcp_mod.McpHttpRequestHandler
JsonRpcResponse = _jsonrpc_mod.JsonRpcResponse

from websockets.datastructures import Headers  # noqa: E402
from websockets.http11 import Request  # noqa: E402
from websockets.protocol import OPEN  # noqa: E402
from websockets.sync.connection import Connection as WebSocketConnection  # noqa: E402
from websockets.sync.server import ServerProtocol  # noqa: E402

from ida_pro_mcp.idalib_pool_manager import PoolManager  # noqa: E402
from ida_pro_mcp.pool_websocket import ExternalInstanceBridge  # noqa: E402

logger = logging.getLogger(__name__)

POOL_WEBSOCKET_MAX_SIZE = 64 * 1024 * 1024
POOL_OUTPUT_CACHE_MAX_SIZE = 100


def configure_ida_directory(ida_dir: str | None) -> str | None:
    """Apply an explicit IDA install directory for subsequently spawned workers."""
    if ida_dir is not None:
        ida_dir = os.path.abspath(os.path.expanduser(ida_dir))
        os.environ["IDADIR"] = ida_dir
    return os.environ.get("IDADIR")


class PoolOutputCache:
    """Pool-owned cache for complete tool results received from backends."""

    def __init__(
        self,
        *,
        base_url: str | None = None,
        max_size: int = POOL_OUTPUT_CACHE_MAX_SIZE,
    ):
        self.base_url = base_url.rstrip("/") if base_url else None
        self.max_size = max(1, max_size)
        self._items: dict[str, Any] = {}
        self._lock = threading.Lock()
        self._request_context = threading.local()

    def put(self, output_id: str, data: Any) -> None:
        with self._lock:
            self._items.pop(output_id, None)
            while len(self._items) >= self.max_size:
                oldest = next(iter(self._items))
                self._items.pop(oldest, None)
            self._items[output_id] = data

    def get(self, output_id: str) -> Any | None:
        with self._lock:
            return self._items.get(output_id)

    def set_request_base_url(self, base_url: str | None) -> None:
        self._request_context.base_url = (
            base_url.rstrip("/") if base_url else None
        )

    def clear_request_base_url(self) -> None:
        self._request_context.base_url = None

    def download_url(self, output_id: str) -> str | None:
        base_url = self.base_url or getattr(
            self._request_context, "base_url", None
        )
        if base_url is None:
            return None
        return f"{base_url}/output/{output_id}.json"


def _complete_forwarded_output(
    response: JsonRpcResponse | None,
) -> tuple[dict, dict, Any, dict] | None:
    """Recover a backend's complete structured result from its text block.

    The IDA-side size limiter truncates ``structuredContent`` but retains the
    original JSON in the first text content block. Pool transports use that
    internal copy to take ownership of the downloadable result.
    """
    if not isinstance(response, dict):
        return None
    result = response.get("result")
    if not isinstance(result, dict):
        return None
    structured = result.get("structuredContent")
    if not isinstance(structured, dict):
        return None
    if structured.get("_output_truncated") is not True:
        return None

    output_id = structured.get("_output_id")
    if (
        not isinstance(output_id, str)
        or re.fullmatch(r"[a-f0-9-]+", output_id) is None
    ):
        return None

    content = result.get("content")
    if not isinstance(content, list):
        return None
    for block in content:
        if not isinstance(block, dict) or block.get("type") != "text":
            continue
        text = block.get("text")
        if not isinstance(text, str):
            continue
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            continue

        complete = parsed if isinstance(parsed, dict) else {"result": parsed}
        total_chars = structured.get("_total_chars")
        if (
            isinstance(total_chars, int)
            and len(json.dumps(complete)) != total_chars
        ):
            continue
        return result, structured, complete, block
    return None


def _prepare_forwarded_large_output(
    response: JsonRpcResponse | None,
    output_cache: PoolOutputCache | None,
    *,
    auth_required: bool,
) -> JsonRpcResponse | None:
    recovered = _complete_forwarded_output(response)
    if recovered is None:
        return response

    result, preview, complete, text_block = recovered
    output_id = preview["_output_id"]
    download_url = output_cache.download_url(output_id) if output_cache else None

    if output_cache is None or download_url is None:
        # stdio has no HTTP endpoint. Return the complete structured result
        # instead of exposing a URL that cannot exist.
        result["structuredContent"] = complete
        return response

    output_cache.put(output_id, complete)
    preview["_download_url"] = download_url
    auth_option = (
        ' -H "Authorization: Bearer $IDA_MCP_AUTH_TOKEN"'
        if auth_required
        else ""
    )
    hint_prefix = (
        "Output truncated. Set IDA_MCP_AUTH_TOKEN to the pool token, then run: "
        if auth_required
        else "Output truncated. Run: "
    )
    preview["_download_hint"] = (
        f"{hint_prefix}mkdir -p .ida-mcp && "
        f"curl{auth_option} -o .ida-mcp/{output_id}.json {download_url}"
    )

    # Do not leak the complete payload through the public MCP text block after
    # the pool has cached it. The backend-to-pool copy is an internal detail.
    text_block["text"] = json.dumps(preview, indent=2)
    return response


def _accept_pool_websocket(handler) -> WebSocketConnection | None:
    """Accept /pool/ws after BaseHTTPRequestHandler parsed the HTTP request."""
    request_headers = Headers(handler.headers.items())
    request = Request(handler.path, request_headers)

    handshake = ServerProtocol(max_size=POOL_WEBSOCKET_MAX_SIZE)
    response = handshake.accept(request)
    handler.request.sendall(response.serialize())
    handler.close_connection = True

    if response.status_code != 101:
        logger.warning(
            "WebSocket handshake rejected: HTTP %s %s",
            response.status_code,
            response.reason_phrase,
        )
        return None

    return WebSocketConnection(
        handler.request,
        ServerProtocol(state=OPEN, max_size=POOL_WEBSOCKET_MAX_SIZE),
        ping_interval=None,
    )

# --------------------------------------------------------------------------
# Management tool names that the proxy intercepts
# --------------------------------------------------------------------------

IDALIB_MANAGEMENT_TOOL_ORDER = [
    "idalib_open",
    "idalib_close",
    "idalib_switch",
    "idalib_list",
    "idalib_current",
    "idalib_save",
    "idalib_health",
    "idalib_warmup",
]

IDALIB_MANAGEMENT_TOOLS = set(IDALIB_MANAGEMENT_TOOL_ORDER)

_LOCAL_PROTOCOL_METHOD_RESULTS: dict[str, dict] = {
    "ping": {},
    "prompts/list": {"prompts": []},
    "resources/list": {"resources": []},
    "resources/templates/list": {"resourceTemplates": []},
}

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
            "Open a binary or IDB for analysis. If the same binary/IDB is "
            "already open, shares the existing session. The pool generates "
            "the returned session_id; always use it for subsequent calls. "
            "Each idalib_open must be balanced by an idalib_close when you "
            "are done."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "input_path": {
                    "type": "string",
                    "description": (
                        "Path to the binary file or IDB (.idb/.i64) to analyze"
                    ),
                },
                "run_auto_analysis": {
                    "type": "boolean",
                    "description": "Run automatic analysis on the binary (default: true)",
                },
                "allow_duplicate_input": {
                    "type": "boolean",
                    "description": (
                        "Allow opening a different IDB for a binary that is "
                        "already open in another session (default: false)"
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
    the refcount/routing semantics. All other IDA tools get an optional
    ``session_id`` parameter injected so clients can route per-tool.
    """
    result = [
        copy.deepcopy(_MGMT_TOOL_OVERRIDES[name])
        for name in IDALIB_MANAGEMENT_TOOL_ORDER
        if name in _MGMT_TOOL_OVERRIDES
    ]
    for tool in tools:
        name = tool.get("name", "")
        if name in IDALIB_MANAGEMENT_TOOLS:
            continue
        tool = copy.deepcopy(tool)
        schema = tool.setdefault("inputSchema", {})
        props = schema.setdefault("properties", {})
        if "session_id" not in props:
            props["session_id"] = _SESSION_ID_SCHEMA
        result.append(tool)
    return result


# --------------------------------------------------------------------------
# Proxy dispatch
# --------------------------------------------------------------------------

def build_dispatch(
    mcp: McpServer,
    pool: PoolManager,
    *,
    output_cache: PoolOutputCache | None = None,
    initial_tools: list[dict] | None = None,
):
    """Patch ``mcp.registry.dispatch`` with pool-aware routing."""

    dispatch_original = mcp.registry.dispatch
    _tools_cache = _prepare_tools(initial_tools) if initial_tools is not None else None
    _tools_cache_lock = threading.Lock()
    _active_forwards_lock = threading.Lock()
    _active_forwards: dict[tuple[str | None, int | str], tuple[Any, object]] = {}

    def _ensure_tools_cache() -> list[dict]:
        nonlocal _tools_cache
        if _tools_cache is None:
            with _tools_cache_lock:
                if _tools_cache is None:
                    raw = pool.discover_tools()
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

    def _tool_error_response(
        request_id: Any, message: str
    ) -> JsonRpcResponse | None:
        if request_id is None:
            return None
        return {
            "jsonrpc": "2.0",
            "result": {
                "content": [{"type": "text", "text": message}],
                "isError": True,
            },
            "id": request_id,
        }

    def _forward_request(inst, request_obj: dict) -> JsonRpcResponse | None:
        request_id = request_obj.get("id")
        key = None
        token = None
        if isinstance(request_id, (int, str)):
            key = (_get_transport_ctx(), request_id)
            token = object()
            with _active_forwards_lock:
                _active_forwards[key] = (inst, token)
        try:
            return pool.forward_raw(inst, request_obj)
        finally:
            if key is not None:
                with _active_forwards_lock:
                    current = _active_forwards.get(key)
                    if current is not None and current[1] is token:
                        _active_forwards.pop(key, None)

    # --- Management tool handlers ---

    def _handle_idalib_open(arguments: dict) -> dict:
        input_path = arguments.get("input_path", "")
        run_auto = arguments.get("run_auto_analysis", True)
        allow_dup = arguments.get("allow_duplicate_input", False)

        result = pool.open_session(
            input_path,
            run_auto_analysis=run_auto,
            allow_duplicate_input=allow_dup,
        )
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

        # Guard: external sessions cannot be force-closed by agents
        with pool._lock:
            sess = pool.sr.get(sid)
        if sess and sess.is_external:
            if force:
                return {
                    "success": False,
                    "error": (
                        "Cannot force-close an externally registered session. "
                        "The session owner must disconnect from the pool."
                    ),
                }
            if ctx:
                bound_sid = pool.get_context_session_id(ctx)
                if bound_sid == sid:
                    pool.unbind_context(ctx)
            new_rc = pool.decrement_refcount(sid)
            return {
                "success": True,
                "closed": False,
                "refcount": new_rc,
                "message": "Reference released. Session is externally managed.",
            }

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
        if getattr(inst, "is_external", False) is True:
            return pool.forward_tool_call(inst, "idb_save", arguments)
        return pool.forward_tool_call(inst, "idalib_save", arguments)

    def _handle_idalib_health(arguments: dict) -> dict:
        sid = arguments.pop("session_id", None)
        ctx = _get_transport_ctx()
        if not sid and ctx:
            sid = pool.get_context_session_id(ctx)
        if not sid:
            return {"ready": False, "error": "No session bound. Use idalib_open first."}
        try:
            sess, inst = pool.resolve_session_instance(sid)
        except (KeyError, RuntimeError) as e:
            return {"ready": False, "error": str(e)}
        if getattr(inst, "is_external", False) is True:
            health = pool.forward_tool_call(inst, "server_health", {})
            return {
                "ready": bool(isinstance(health, dict) and health.get("status") == "ok"),
                "session": sess.to_dict(refcount=pool.get_refcount(sid)),
                "health": health,
            }
        return pool.forward_tool_call(inst, "idalib_health", arguments)

    def _handle_idalib_warmup(arguments: dict) -> dict:
        sid = arguments.pop("session_id", None)
        ctx = _get_transport_ctx()
        if not sid and ctx:
            sid = pool.get_context_session_id(ctx)
        if not sid:
            return {"ready": False, "error": "No session bound. Use idalib_open first."}
        try:
            sess, inst = pool.resolve_session_instance(sid)
        except (KeyError, RuntimeError) as e:
            return {"ready": False, "error": str(e)}
        if getattr(inst, "is_external", False) is True:
            warmup = pool.forward_tool_call(inst, "server_warmup", arguments)
            return {
                "ready": bool(isinstance(warmup, dict) and warmup.get("ok")),
                "session": sess.to_dict(refcount=pool.get_refcount(sid)),
                "warmup": warmup,
            }
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
                return _tool_error_response(request_id, str(e))
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
            return _tool_error_response(request_id, str(e.args[0]))

        try:
            _sess, inst = pool.resolve_session_instance(session_id)
        except (KeyError, RuntimeError) as e:
            message = str(e.args[0]) if isinstance(e, KeyError) else str(e)
            return _tool_error_response(request_id, message)

        forwarded = copy.deepcopy(request_obj)
        fwd_args = forwarded.get("params", {}).get("arguments", {})
        fwd_args.pop("session_id", None)

        response = _forward_request(inst, forwarded)
        return _prepare_forwarded_large_output(
            response,
            output_cache,
            auth_required=bool(mcp.auth_token),
        )

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
        if method == "notifications/cancelled":
            params = request_obj.get("params") or {}
            cancelled_id = params.get("requestId") if isinstance(params, dict) else None
            if isinstance(cancelled_id, (int, str)):
                key = (_get_transport_ctx(), cancelled_id)
                with _active_forwards_lock:
                    active = _active_forwards.get(key)
                if active is not None:
                    pool.cancel_instance_request(active[0], request_obj)
            return dispatch_original(request)
        if method.startswith("notifications/"):
            return dispatch_original(request)

        if method == "tools/list":
            return _handle_tools_list(request_obj)

        if method in _LOCAL_PROTOCOL_METHOD_RESULTS:
            return {
                "jsonrpc": "2.0",
                "result": copy.deepcopy(_LOCAL_PROTOCOL_METHOD_RESULTS[method]),
                "id": request_id,
            }

        if method == "tools/call":
            try:
                return _handle_tools_call(request_obj)
            except Exception as e:
                reference = secrets.token_hex(6)
                logger.exception(
                    "Unhandled pool tool error [%s]: %s", reference, e
                )
                return _tool_error_response(
                    request_id,
                    f"Internal tool error (reference: {reference})",
                )

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
        return _forward_request(inst, request_obj)

    mcp.registry.dispatch = dispatch_proxy


# --------------------------------------------------------------------------
# WebSocket handler for external plugin registration
# --------------------------------------------------------------------------

def build_pool_handler_class(
    pool: PoolManager,
    output_cache: PoolOutputCache | None = None,
):
    """Create a request handler class with WebSocket support for /pool/ws."""

    class PoolHttpRequestHandler(McpHttpRequestHandler):

        def do_POST(self):
            if output_cache is None:
                super().do_POST()
                return

            host = self.headers.get("Host")
            request_base_url = None
            if host and re.fullmatch(r"[A-Za-z0-9._:\[\]-]+", host):
                request_base_url = f"http://{host}"
            output_cache.set_request_base_url(request_base_url)
            try:
                super().do_POST()
            finally:
                output_cache.clear_request_base_url()

        def do_GET(self):
            from urllib.parse import urlparse
            path = urlparse(self.path).path
            output_match = re.fullmatch(r"/output/([a-f0-9-]+)\.json", path)
            if output_match and output_cache is not None:
                if not self._check_auth():
                    return
                self._handle_output_download(output_match.group(1))
            elif path == "/pool/ws":
                if not self._check_auth():
                    return
                self._handle_pool_ws()
            else:
                super().do_GET()

        def _handle_output_download(self, output_id: str):
            data = output_cache.get(output_id) if output_cache else None
            if data is None:
                self.send_error(404, "Output not found or expired")
                return

            body = json.dumps(data, indent=2).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header(
                "Content-Disposition",
                f'attachment; filename="{output_id}.json"',
            )
            self.send_cors_headers()
            self.end_headers()
            self.wfile.write(body)

        def _handle_pool_ws(self):
            ws = _accept_pool_websocket(self)
            if ws is None:
                return

            bridge = ExternalInstanceBridge(ws)
            session_id = None

            try:
                raw = ws.recv()
                reg = json.loads(raw)
                if reg.get("type") != "register":
                    ws.send(json.dumps({"success": False, "error": "Expected register message"}))
                    return

                result = pool.register_external(
                    ws_bridge=bridge,
                    input_path=reg.get("input_path", ""),
                    idb_path=reg.get("idb_path", ""),
                    allow_duplicate_input=reg.get("allow_duplicate_input", False),
                )
                ws.send(json.dumps(result))

                if not result.get("success"):
                    return

                session_id = result["session"]["session_id"]
                logger.info(
                    "External plugin registered: session=%s input=%s",
                    session_id, reg.get("input_path"),
                )

                def on_check_agents():
                    return pool.get_external_agent_count(session_id)

                bridge.run_loop(on_check_agents=on_check_agents)

            except Exception as e:
                logger.info("External plugin connection ended: %s", e)
            finally:
                bridge.alive = False
                if session_id:
                    pool.unregister_external(session_id)
                    logger.info("External plugin unregistered: session=%s", session_id)
                try:
                    ws.close()
                except Exception:
                    pass

    return PoolHttpRequestHandler


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
        "--runtime-dir", type=str, default=None,
        help="Directory for backend logs (default: auto temp dir)",
    )
    parser.add_argument(
        "--ida-dir", type=str, default=None,
        help="IDA installation directory (overrides IDADIR for spawned backends)",
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
        "--auth-token", type=str,
        default=os.environ.get("IDA_MCP_AUTH_TOKEN"),
        help="Bearer token for HTTP authentication (or set IDA_MCP_AUTH_TOKEN)",
    )
    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level)

    ida_dir = configure_ida_directory(args.ida_dir)
    if ida_dir:
        logger.info("Using IDA installation: %s", ida_dir)

    idalib_args: list[str] = []
    if args.verbose:
        idalib_args.append("--verbose")
    if args.safe:
        idalib_args.append("--safe")

    pool = PoolManager(
        runtime_dir=args.runtime_dir,
        idalib_args=idalib_args,
    )

    mcp = McpServer("ida-pro-mcp")
    mcp.require_streamable_http_session = True
    if args.auth_token:
        mcp.auth_token = args.auth_token
    output_cache = (
        None
        if args.transport == "stdio"
        else PoolOutputCache(base_url=os.environ.get("IDA_MCP_URL"))
    )

    def request_shutdown(signum, frame):
        logger.info("Shutdown requested")
        raise SystemExit(0)

    signal.signal(signal.SIGINT, request_shutdown)
    signal.signal(signal.SIGTERM, request_shutdown)

    try:
        logger.info("Checking IDA backend startup...")
        try:
            initial_tools = pool.discover_tools()
        except Exception as e:
            print(f"Error: IDA backend startup check failed: {e}", file=sys.stderr)
            raise SystemExit(1) from None
        logger.info("IDA backend ready; discovered %d tools", len(initial_tools))

        build_dispatch(
            mcp,
            pool,
            output_cache=output_cache,
            initial_tools=initial_tools,
        )

        transport = args.transport
        if transport == "stdio":
            mcp.stdio()
        else:
            from urllib.parse import urlparse
            url = urlparse(transport)
            if not url.hostname or not url.port:
                print(f"Error: invalid transport URL: {transport}", file=sys.stderr)
                sys.exit(1)
            handler_cls = build_pool_handler_class(pool, output_cache)
            mcp.serve(host=url.hostname, port=url.port, background=False,
                      request_handler=handler_cls)
    finally:
        logger.info("Shutting down pool...")
        pool.shutdown_all()


if __name__ == "__main__":
    main()
