"""idalib Pool Manager — manages a pool of idalib_server subprocess instances.

Each instance is an independent idalib_server process communicating over a
Unix domain socket.  The pool enforces a 1-instance-per-session model: every
instance holds at most one active IDB at a time.

Key invariants
--------------
* Session path indexes share an already-open binary/IDB unless the caller
  explicitly confirms a duplicate input.
* Sessions are always "hot" (backed by a dedicated running instance). Opening
  a new session starts a new instance; closing the session kills it.
* Each session has a reference count tracking how many agents have it open.
  When the refcount reaches zero the session is closed automatically.
* ``_context_bindings`` maps MCP transport session IDs to IDA session IDs,
  providing per-agent routing so multiple agents sharing one MCP endpoint
  can work on different IDBs without interfering.
* Tool discovery uses a short-lived instance that is terminated immediately
  after its schemas have been read.
"""

from __future__ import annotations

import hashlib
import logging
import multiprocessing
import ntpath
import os
import re
import secrets
import tempfile
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

from ida_pro_mcp.backend_bootstrap import run_backend_process
from ida_pro_mcp.backend_ipc import (
    BackendIpcError,
    BackendProcessExited,
    make_message,
    send_message,
    wait_for_message,
)

logger = logging.getLogger(__name__)


_WINDOWS_ABS_RE = re.compile(r"^[A-Za-z]:[\\/]")
_SESSION_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


class PoolShuttingDownError(RuntimeError):
    pass


def _looks_windows_abs(path: str) -> bool:
    return bool(_WINDOWS_ABS_RE.match(path) or path.startswith("\\\\"))


def _normalize_path(path: str) -> str:
    if not path:
        return ""
    if _looks_windows_abs(path):
        return ntpath.normpath(path)
    return os.path.abspath(path)


def _path_basename(path: str) -> str:
    if not path:
        return ""
    if _looks_windows_abs(path) or "\\" in path:
        return ntpath.basename(path)
    return os.path.basename(path)


def _session_base_name(path: str) -> str:
    name = _path_basename(path) or "session"
    root, ext = os.path.splitext(name)
    if ext.lower() in {".idb", ".i64"} and root:
        name = root
    name = _SESSION_NAME_RE.sub("_", name).strip("._-")
    return name or "session"

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class SessionInfo:
    session_id: str
    input_path: str
    idb_path: str
    instance_index: int
    is_external: bool = False
    last_accessed: float = field(default_factory=time.monotonic)
    created_at: float = field(default_factory=time.monotonic)

    def to_dict(self, *, refcount: int = 0) -> dict:
        return {
            "session_id": self.session_id,
            "input_path": self.input_path,
            "idb_path": self.idb_path,
            "filename": _path_basename(self.input_path),
            "refcount": refcount,
            "is_external": self.is_external,
            "last_accessed": self.last_accessed,
            "instance_index": self.instance_index,
        }


@dataclass
class InstanceInfo:
    index: int
    socket_path: str
    process: Any | None
    rpc_connection: Any | None = None
    control_connection: Any | None = None
    session_id: str | None = None
    ws_bridge: Any | None = None  # ExternalInstanceBridge for external instances
    closing: bool = False
    operation_lock: threading.RLock = field(
        default_factory=threading.RLock, repr=False
    )
    rpc_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    control_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    @property
    def is_external(self) -> bool:
        return self.ws_bridge is not None

    def is_alive(self) -> bool:
        if self.is_external:
            return self.ws_bridge is not None and self.ws_bridge.alive
        if self.process is None:
            return False
        if hasattr(self.process, "poll"):
            return self.process.poll() is None
        try:
            return self.process.is_alive()
        except ValueError:
            return False


# ---------------------------------------------------------------------------
# Instance Manager — subprocess lifecycle + HTTP forwarding
# ---------------------------------------------------------------------------

class InstanceManager:
    """Manages idalib_server subprocesses and communicates over Unix sockets."""

    def __init__(
        self,
        socket_dir: str,
        idalib_args: list[str] | None = None,
        *,
        mp_context=None,
        worker_target=None,
    ):
        self.socket_dir = socket_dir
        self.idalib_args = idalib_args or []
        self._mp_context = mp_context or multiprocessing.get_context("spawn")
        self._worker_target = worker_target or run_backend_process
        self.instances: list[InstanceInfo] = []
        self._next_index = 0
        self._lock = threading.RLock()

    def spawn(self) -> InstanceInfo:
        with self._lock:
            idx = self._next_index
            self._next_index += 1
        log_path = os.path.join(self.socket_dir, f"{idx}.log")
        parent_rpc, child_rpc = self._mp_context.Pipe(duplex=True)
        child_control, parent_control = self._mp_context.Pipe(duplex=False)
        proc = self._mp_context.Process(
            target=self._worker_target,
            args=(child_rpc, child_control, log_path, list(self.idalib_args)),
            name=f"idalib-backend-{idx}",
        )
        logger.info("Spawning instance %d (log: %s)", idx, log_path)
        try:
            proc.start()
        except Exception:
            parent_rpc.close()
            child_rpc.close()
            child_control.close()
            parent_control.close()
            raise
        child_rpc.close()
        child_control.close()
        inst = InstanceInfo(
            index=idx,
            socket_path="",
            process=proc,
            rpc_connection=parent_rpc,
            control_connection=parent_control,
        )
        with self._lock:
            self.instances.append(inst)
        try:
            self._wait_for_ready(inst)
        except Exception:
            if inst.is_alive():
                self.kill(inst)
            else:
                self.discard(inst)
            raise
        return inst

    def register_external(self, ws_bridge) -> InstanceInfo:
        """Register an external instance connected via WebSocket."""
        with self._lock:
            idx = self._next_index
            self._next_index += 1
        inst = InstanceInfo(
            index=idx,
            socket_path="",
            process=None,
            ws_bridge=ws_bridge,
        )
        with self._lock:
            self.instances.append(inst)
        logger.info("Registered external instance %d", idx)
        return inst

    def kill(self, inst: InstanceInfo) -> None:
        if inst.is_external:
            logger.info("Removing external instance %d", inst.index)
            if inst.ws_bridge:
                inst.ws_bridge.alive = False
        else:
            logger.info("Killing instance %d (pid %d)", inst.index, inst.process.pid)
            try:
                self.send_control(inst, "shutdown")
                inst.process.join(timeout=10)
                if inst.is_alive():
                    inst.process.terminate()
                    inst.process.join(timeout=5)
                if inst.is_alive():
                    inst.process.kill()
                    inst.process.join(timeout=5)
            finally:
                self._close_local_resources(inst)
        with self._lock:
            if inst in self.instances:
                self.instances.remove(inst)

    def discard(self, inst: InstanceInfo) -> None:
        """Forget an instance that is already unusable."""
        if inst.is_external and inst.ws_bridge:
            inst.ws_bridge.alive = False
        if not inst.is_external:
            self._close_local_resources(inst)
        with self._lock:
            if inst in self.instances:
                self.instances.remove(inst)

    def kill_all(self) -> None:
        with self._lock:
            instances = list(self.instances)
        for inst in instances:
            self.kill(inst)

    def find(self, index: int) -> InstanceInfo | None:
        with self._lock:
            for inst in self.instances:
                if inst.index == index:
                    return inst
        return None

    def snapshot(self) -> list[InstanceInfo]:
        with self._lock:
            return list(self.instances)

    def contains(self, inst: InstanceInfo) -> bool:
        with self._lock:
            return inst in self.instances

    def _close_local_resources(self, inst: InstanceInfo) -> None:
        for attribute in ("rpc_connection", "control_connection"):
            connection = getattr(inst, attribute)
            if connection is not None:
                try:
                    connection.close()
                except (OSError, ValueError):
                    pass
                setattr(inst, attribute, None)
        process = inst.process
        if process is not None and not inst.is_alive():
            try:
                process.close()
            except (OSError, ValueError):
                pass

    def send_control(self, inst: InstanceInfo, command: str) -> bool:
        if not inst.is_alive() or inst.control_connection is None:
            return False
        with inst.control_lock:
            try:
                send_message(
                    inst.control_connection,
                    make_message(command),
                )
                return True
            except (BackendIpcError, BrokenPipeError, OSError, ValueError):
                return False

    def _wait_for_ready(self, inst: InstanceInfo, timeout: float = 120) -> None:
        if inst.process is None or inst.rpc_connection is None:
            raise RuntimeError(f"Instance {inst.index} has no local IPC channel")
        try:
            message = wait_for_message(
                inst.rpc_connection,
                inst.process.sentinel,
                timeout,
            )
        except BackendProcessExited as e:
            raise RuntimeError(
                f"Instance {inst.index} exited prematurely "
                f"(code {inst.process.exitcode})"
            ) from e
        if message["type"] == "startup_error":
            raise RuntimeError(
                f"Instance {inst.index} failed to start: {message.get('error')}"
            )
        if message["type"] != "ready":
            raise RuntimeError(
                f"Instance {inst.index} sent unexpected startup message: "
                f"{message['type']}"
            )
        logger.info("Instance %d ready (pid %d)", inst.index, inst.process.pid)

    # --- HTTP forwarding ---

    def forward_tool_call(
        self, inst: InstanceInfo, tool_name: str, arguments: dict
    ) -> Any:
        request = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
            "id": 1,
        }
        resp = self.forward_raw(inst, request)
        result = resp.get("result", resp)
        sc = result.get("structuredContent") if isinstance(result, dict) else None
        return sc if sc is not None else result

    def forward_raw(self, inst: InstanceInfo, request: dict) -> dict:
        if inst.is_external:
            return inst.ws_bridge.forward_request(request)
        if inst.process is None or inst.rpc_connection is None:
            raise RuntimeError(f"Instance {inst.index} has no local IPC channel")
        with inst.rpc_lock:
            send_message(
                inst.rpc_connection,
                make_message("request", payload=request),
            )
            message = wait_for_message(
                inst.rpc_connection,
                inst.process.sentinel,
                300,
            )
        if message["type"] in {"error", "startup_error"}:
            raise RuntimeError(message.get("error") or "backend IPC error")
        if message["type"] != "response":
            raise RuntimeError(
                f"Instance {inst.index} sent unexpected RPC message: "
                f"{message['type']}"
            )
        response = message.get("payload")
        if not isinstance(response, dict):
            raise RuntimeError("Backend returned a non-object JSON-RPC response")
        return response

    def forward_tools_list(self, inst: InstanceInfo) -> list[dict]:
        request = {"jsonrpc": "2.0", "method": "tools/list", "id": 1}
        resp = self.forward_raw(inst, request)
        return resp.get("result", {}).get("tools", [])


# ---------------------------------------------------------------------------
# Session Registry — session state, path dedup, context bindings, refcounts
# ---------------------------------------------------------------------------

class SessionRegistry:
    """Tracks session metadata, path uniqueness, context bindings, and refcounts.

    Two path indices provide dedup:
    - ``_input_path_index``: canonical binary path → list of session IDs
      (one-to-many when ``allow_duplicate_input`` is used)
    - ``_idb_path_index``: IDB file path → session ID (always one-to-one)
    """

    def __init__(self):
        self.sessions: dict[str, SessionInfo] = {}
        self._input_path_index: dict[str, list[str]] = {}
        self._idb_path_index: dict[str, str] = {}
        self._context_bindings: dict[str, str] = {}
        self._refcounts: dict[str, int] = {}

    def create(
        self,
        session_id: str,
        input_path: str,
        idb_path: str,
        instance_index: int,
        *,
        is_external: bool = False,
    ) -> SessionInfo:
        if session_id in self.sessions:
            raise ValueError(f"Session already exists: {session_id}")
        sess = SessionInfo(
            session_id=session_id,
            input_path=input_path,
            idb_path=idb_path,
            instance_index=instance_index,
            is_external=is_external,
        )
        self.sessions[session_id] = sess
        self._input_path_index.setdefault(input_path, []).append(session_id)
        if idb_path:
            self._idb_path_index[idb_path] = session_id
        self._refcounts[session_id] = 0
        return sess

    def remove(self, session_id: str) -> SessionInfo | None:
        """Permanently remove a session."""
        sess = self.sessions.pop(session_id, None)
        if sess:
            sids = self._input_path_index.get(sess.input_path, [])
            if session_id in sids:
                sids.remove(session_id)
            if not sids:
                self._input_path_index.pop(sess.input_path, None)
            if sess.idb_path:
                self._idb_path_index.pop(sess.idb_path, None)
        self._refcounts.pop(session_id, None)
        self._unbind_session_everywhere(session_id)
        return sess

    def get(self, session_id: str) -> SessionInfo | None:
        return self.sessions.get(session_id)

    def touch(self, session_id: str) -> None:
        sess = self.sessions.get(session_id)
        if sess:
            sess.last_accessed = time.monotonic()

    def find_by_input_path(self, input_path: str) -> list[str]:
        """Return all session_ids with this input_path."""
        return list(self._input_path_index.get(input_path, []))

    def find_by_idb_path(self, idb_path: str) -> str | None:
        """Return the session_id for an exact IDB path match."""
        return self._idb_path_index.get(idb_path)

    def disambiguate(self, session_ids: list[str], input_path: str) -> str:
        """Pick the best session when multiple share the same input_path.

        Priority: IDB in the same directory as input_path > earliest created.
        """
        input_dir = os.path.dirname(input_path)
        same_dir = [
            sid for sid in session_ids
            if os.path.dirname(self.sessions[sid].idb_path) == input_dir
        ]
        if same_dir:
            return same_dir[0]
        # Fall back to earliest by created_at
        return min(session_ids, key=lambda sid: self.sessions[sid].created_at)

    def generate_id_for_path(self, display_path: str, identity_path: str) -> str:
        base = _session_base_name(display_path)
        digest = hashlib.sha256(identity_path.encode("utf-8")).hexdigest()[:6]
        candidate = f"{base}_{digest}"
        while candidate in self.sessions:
            candidate = f"{base}_{digest}_{secrets.token_hex(3)}"
        return candidate

    # --- Context bindings (no refcount effect) ---

    def bind_context(self, context_id: str, session_id: str) -> None:
        """Set the routing for a transport context. No refcount change."""
        if session_id not in self.sessions:
            raise ValueError(f"Session not found: {session_id}")
        self._context_bindings[context_id] = session_id

    def unbind_context(self, context_id: str) -> str | None:
        """Remove a context binding. Returns the old session_id or None."""
        return self._context_bindings.pop(context_id, None)

    def get_context_session_id(self, context_id: str) -> str | None:
        """Return the session_id bound to a context, or None."""
        return self._context_bindings.get(context_id)

    def _unbind_session_everywhere(self, session_id: str) -> None:
        """Remove all context bindings pointing to a session."""
        stale = [ctx for ctx, sid in self._context_bindings.items() if sid == session_id]
        for ctx in stale:
            del self._context_bindings[ctx]

    # --- Refcounts ---

    def increment_refcount(self, session_id: str) -> int:
        rc = self._refcounts.get(session_id, 0) + 1
        self._refcounts[session_id] = rc
        return rc

    def decrement_refcount(self, session_id: str) -> int:
        rc = max(0, self._refcounts.get(session_id, 0) - 1)
        self._refcounts[session_id] = rc
        return rc

    def get_refcount(self, session_id: str) -> int:
        return self._refcounts.get(session_id, 0)

    # --- Listing ---

    def list_all(self, context_id: str | None = None) -> dict:
        context_session_id = self._context_bindings.get(context_id) if context_id else None
        return {
            "sessions": [
                {
                    **s.to_dict(refcount=self.get_refcount(s.session_id)),
                    "is_current_context": s.session_id == context_session_id,
                }
                for s in self.sessions.values()
            ],
            "count": len(self.sessions),
            "current_context_session_id": context_session_id,
        }


# ---------------------------------------------------------------------------
# Pool Manager — binds instances and sessions together
# ---------------------------------------------------------------------------

class PoolManager:
    _RUNNING = "running"
    _SHUTTING_DOWN = "shutting_down"
    _STOPPED = "stopped"

    def __init__(
        self,
        socket_dir: str | None = None,
        idalib_args: list[str] | None = None,
    ):
        socket_dir = socket_dir or tempfile.mkdtemp(prefix="idalib-pool-")
        os.makedirs(socket_dir, exist_ok=True)

        self.im = InstanceManager(socket_dir, idalib_args)
        self.sr = SessionRegistry()
        self._lock = threading.Lock()
        self._condition = threading.Condition(self._lock)
        self._state = self._RUNNING
        self._active_operations = 0
        self._opening_inputs: dict[str, int] = {}
        self._reserved_session_ids: set[str] = set()

    @contextmanager
    def _operation(self):
        with self._condition:
            if self._state != self._RUNNING:
                raise PoolShuttingDownError("Pool is shutting down")
            self._active_operations += 1
        try:
            yield
        finally:
            with self._condition:
                self._active_operations -= 1
                if self._active_operations == 0:
                    self._condition.notify_all()

    def _reserve_session_id_locked(self, display_path: str, identity_path: str) -> str:
        session_id = self.sr.generate_id_for_path(display_path, identity_path)
        while session_id in self._reserved_session_ids:
            session_id = f"{session_id}_{secrets.token_hex(3)}"
        self._reserved_session_ids.add(session_id)
        return session_id

    # ------------------------------------------------------------------
    # High-level operations
    # ------------------------------------------------------------------

    def discover_tools(self) -> list[dict]:
        """Discover tool schemas using a short-lived backend instance."""
        with self._operation():
            inst = self.im.spawn()
            try:
                with inst.operation_lock:
                    return self.im.forward_tools_list(inst)
            finally:
                inst.closing = True
                if inst.is_alive():
                    self.im.kill(inst)
                else:
                    self.im.discard(inst)

    def _terminate_unattached_instance(self, inst: InstanceInfo) -> None:
        """Stop a backend that failed before it became a registered session."""
        if inst.session_id is not None:
            return
        inst.closing = True
        if inst.is_alive():
            self.im.kill(inst)
        else:
            self.im.discard(inst)

    def shutdown_all(self) -> None:
        with self._condition:
            if self._state == self._STOPPED:
                return
            if self._state == self._SHUTTING_DOWN:
                while self._state != self._STOPPED:
                    self._condition.wait()
                return

            self._state = self._SHUTTING_DOWN
            while self._active_operations:
                self._condition.wait()

            instances_to_save = [
                inst for inst in self.im.snapshot()
                if inst.session_id and not inst.is_external
            ]
            for inst in self.im.snapshot():
                inst.closing = True

        try:
            for inst in instances_to_save:
                with inst.operation_lock:
                    if self._save_instance_for_shutdown(inst):
                        self._close_instance_for_shutdown(inst)
        finally:
            with self._condition:
                try:
                    self.im.kill_all()
                    self.sr.sessions.clear()
                    self.sr._input_path_index.clear()
                    self.sr._idb_path_index.clear()
                    self.sr._context_bindings.clear()
                    self.sr._refcounts.clear()
                    self._opening_inputs.clear()
                    self._reserved_session_ids.clear()
                finally:
                    self._state = self._STOPPED
                    self._condition.notify_all()

    def _save_instance_for_shutdown(self, inst: InstanceInfo) -> bool:
        try:
            result = self.im.forward_tool_call(inst, "idalib_save", {})
        except Exception as e:
            logger.warning(
                "Failed to save instance %d (session %s): %s; continuing shutdown",
                inst.index, inst.session_id, e,
            )
            return False

        if isinstance(result, dict) and result.get("ok") is False:
            logger.warning(
                "Failed to save instance %d (session %s): %s; continuing shutdown",
                inst.index, inst.session_id,
                result.get("error") or result,
            )
            return False

        return True

    def _close_instance_for_shutdown(self, inst: InstanceInfo) -> None:
        try:
            result = self.im.forward_tool_call(
                inst, "idalib_close", {"session_id": inst.session_id}
            )
        except Exception as e:
            logger.warning(
                "Failed to close instance %d (session %s): %s; continuing shutdown",
                inst.index, inst.session_id, e,
            )
            return

        if isinstance(result, dict) and result.get("error"):
            logger.warning(
                "Failed to close instance %d (session %s): %s; continuing shutdown",
                inst.index, inst.session_id, result["error"],
            )

    def open_session(
        self,
        binary_path: str,
        run_auto_analysis: bool = True,
        allow_duplicate_input: bool = False,
    ) -> dict:
        try:
            with self._operation():
                return self._open_session(
                    binary_path,
                    run_auto_analysis=run_auto_analysis,
                    allow_duplicate_input=allow_duplicate_input,
                )
        except PoolShuttingDownError as e:
            return {"success": False, "error": str(e)}

    def _open_session(
        self,
        binary_path: str,
        run_auto_analysis: bool,
        allow_duplicate_input: bool,
    ) -> dict:
        resolved = _normalize_path(binary_path)
        is_idb = resolved.endswith((".idb", ".i64"))

        with self._condition:
            while True:
                if self._state != self._RUNNING:
                    raise PoolShuttingDownError("Pool is shutting down")
                if not allow_duplicate_input and self._opening_inputs.get(resolved, 0):
                    self._condition.wait()
                    continue

                # IDB path: check exact IDB match first
                if is_idb:
                    existing_sid = self.sr.find_by_idb_path(resolved)
                    if existing_sid is not None:
                        self.sr.touch(existing_sid)
                        sess = self.sr.get(existing_sid)
                        return {
                            "success": True,
                            "existing": True,
                            "session": sess.to_dict(
                                refcount=self.sr.get_refcount(existing_sid)
                            ),
                            "message": f"IDB already open as session '{existing_sid}'.",
                        }
                else:
                    matching_sids = self.sr.find_by_input_path(resolved)
                    if matching_sids:
                        existing_sid = (
                            matching_sids[0]
                            if len(matching_sids) == 1
                            else self.sr.disambiguate(matching_sids, resolved)
                        )
                        self.sr.touch(existing_sid)
                        sess = self.sr.get(existing_sid)
                        return {
                            "success": True,
                            "existing": True,
                            "session": sess.to_dict(
                                refcount=self.sr.get_refcount(existing_sid)
                            ),
                            "message": (
                                f"Binary already open as session '{existing_sid}'."
                            ),
                        }

                session_id = self._reserve_session_id_locked(resolved, resolved)
                self._opening_inputs[resolved] = (
                    self._opening_inputs.get(resolved, 0) + 1
                )
                break

        inst: InstanceInfo | None = None
        try:
            last_error: Exception | None = None
            for attempt in range(2):
                inst = self.im.spawn()
                try:
                    with inst.operation_lock:
                        resp = self.im.forward_tool_call(inst, "idalib_open", {
                            "input_path": resolved,
                            "run_auto_analysis": run_auto_analysis,
                            "session_id": session_id,
                        })
                    break
                except (BackendIpcError, ConnectionRefusedError, OSError) as e:
                    last_error = e
                    logger.warning(
                        "Backend instance %d unavailable while opening %s: %s",
                        inst.index, resolved, e,
                    )
                    self._terminate_unattached_instance(inst)
                    if attempt == 0:
                        continue
                    return {
                        "success": False,
                        "error": (
                            "Backend instance unavailable while opening "
                            f"{resolved}: {last_error}"
                        ),
                    }
            else:
                return {
                    "success": False,
                    "error": (
                        "Backend instance unavailable while opening "
                        f"{resolved}: {last_error}"
                    ),
                }

            if isinstance(resp, dict) and resp.get("error"):
                self._terminate_unattached_instance(inst)
                return resp

            backend_session = (
                resp.get("session", {}) if isinstance(resp, dict) else {}
            )
            canonical_input = backend_session.get("input_path", resolved)
            idb_path = backend_session.get("idb_path", "")

            conflict_sid: str | None = None
            with self._lock:
                canonical_input = (
                    _normalize_path(canonical_input) if canonical_input else resolved
                )
                if idb_path:
                    idb_path = _normalize_path(idb_path)

                existing_for_input = self.sr.find_by_input_path(canonical_input)
                if existing_for_input and not allow_duplicate_input:
                    conflict_sid = existing_for_input[0]
                    inst.closing = True
                else:
                    sess = self.sr.create(
                        session_id, canonical_input, idb_path, inst.index
                    )
                    inst.session_id = session_id

            if conflict_sid is not None:
                try:
                    with inst.operation_lock:
                        self.im.forward_tool_call(
                            inst, "idalib_close", {"session_id": session_id}
                        )
                except Exception:
                    logger.warning(
                        "Failed to roll back conflicting session %s", session_id
                    )
                self.im.kill(inst)
                return {
                    "success": False,
                    "error": (
                        f"Binary already open as session '{conflict_sid}'. "
                        "Use allow_duplicate_input=true to open another IDB "
                        "for the same binary."
                    ),
                }

            return {
                "success": True,
                "existing": False,
                "session": sess.to_dict(
                    refcount=self.sr.get_refcount(session_id)
                ),
                "message": f"Session created: {session_id}",
            }
        finally:
            if (
                inst is not None
                and inst.session_id is None
                and self.im.contains(inst)
            ):
                self._terminate_unattached_instance(inst)
            with self._condition:
                self._reserved_session_ids.discard(session_id)
                remaining = self._opening_inputs.get(resolved, 0) - 1
                if remaining > 0:
                    self._opening_inputs[resolved] = remaining
                else:
                    self._opening_inputs.pop(resolved, None)
                self._condition.notify_all()

    def close_session(self, session_id: str) -> dict:
        try:
            with self._operation():
                return self._close_session(session_id)
        except PoolShuttingDownError as e:
            return {"success": False, "error": str(e)}

    def _close_session(self, session_id: str) -> dict:
        with self._lock:
            sess = self.sr.get(session_id)
            if sess is None:
                return {"success": False, "error": f"Session not found: {session_id}"}
            inst = self.im.find(sess.instance_index)
            if inst is None:
                self.sr.remove(session_id)
                return {"success": True, "closed": True, "message": f"Session cleaned up: {session_id}"}
            if inst.closing:
                return {
                    "success": False,
                    "closed": False,
                    "error": f"Session is already closing: {session_id}",
                }
            inst.closing = True

        with inst.operation_lock:
            if not sess.is_external:
                try:
                    self.im.forward_tool_call(inst, "idalib_save", {})
                except Exception:
                    logger.warning("Failed to save before closing session %s", session_id)
                try:
                    self.im.forward_tool_call(
                        inst, "idalib_close", {"session_id": session_id}
                    )
                except Exception:
                    logger.warning("Failed to forward close for session %s", session_id)

        with self._lock:
            self.sr.remove(session_id)
            inst.session_id = None

        self.im.kill(inst)

        return {"success": True, "closed": True, "message": f"Session closed: {session_id}"}

    # ------------------------------------------------------------------
    # External instance registration
    # ------------------------------------------------------------------

    def register_external(
        self,
        ws_bridge,
        input_path: str,
        idb_path: str,
        allow_duplicate_input: bool = False,
    ) -> dict:
        try:
            with self._operation():
                return self._register_external(
                    ws_bridge,
                    input_path,
                    idb_path,
                    allow_duplicate_input=allow_duplicate_input,
                )
        except PoolShuttingDownError as e:
            return {"success": False, "error": str(e)}

    def _register_external(
        self,
        ws_bridge,
        input_path: str,
        idb_path: str,
        allow_duplicate_input: bool = False,
    ) -> dict:
        """Register an external IDA plugin instance via WebSocket."""
        input_path = _normalize_path(input_path)
        if idb_path:
            idb_path = _normalize_path(idb_path)

        with self._lock:
            # Check idb_path conflict (same IDB already open)
            if idb_path and self.sr.find_by_idb_path(idb_path):
                existing_sid = self.sr.find_by_idb_path(idb_path)
                return {
                    "success": False,
                    "error": f"IDB already open as session '{existing_sid}'.",
                }

            # Check input_path conflict
            existing_for_input = self.sr.find_by_input_path(input_path)
            if existing_for_input and not allow_duplicate_input:
                return {
                    "success": False,
                    "needs_confirm": True,
                    "conflict_session": existing_for_input[0],
                    "message": (
                        f"Binary already open as session "
                        f"'{existing_for_input[0]}'. Confirm to register "
                        f"a second session for the same binary."
                    ),
                }

            inst = self.im.register_external(ws_bridge)
            identity_path = idb_path or input_path
            display_path = input_path or identity_path
            session_id = self.sr.generate_id_for_path(display_path, identity_path)

            sess = self.sr.create(
                session_id, input_path, idb_path, inst.index,
                is_external=True,
            )
            inst.session_id = session_id
            # User's baseline refcount
            self.sr.increment_refcount(session_id)

        return {
            "success": True,
            "session": sess.to_dict(refcount=self.sr.get_refcount(session_id)),
        }

    def unregister_external(self, session_id: str) -> dict:
        """Remove an external session from the pool."""
        try:
            with self._operation():
                return self._unregister_external(session_id)
        except PoolShuttingDownError as e:
            return {"success": False, "error": str(e)}

    def _unregister_external(self, session_id: str) -> dict:
        with self._lock:
            sess = self.sr.get(session_id)
            if not sess or not sess.is_external:
                return {"success": False, "error": "External session not found"}
            agents = max(0, self.sr.get_refcount(session_id) - 1)
            self.sr.remove(session_id)
            inst = self.im.find(sess.instance_index)
            if inst:
                inst.closing = True
                inst.session_id = None
        if inst:
            with inst.operation_lock:
                self.im.kill(inst)
        return {"success": True, "active_agents": agents}

    def get_external_agent_count(self, session_id: str) -> int:
        with self._lock:
            return max(0, self.sr.get_refcount(session_id) - 1)

    def resolve_session_instance(
        self, session_id: str
    ) -> tuple[SessionInfo, InstanceInfo]:
        """Return (session, instance) for a hot session."""
        with self._lock:
            sess = self.sr.get(session_id)
            if sess is None:
                raise KeyError(
                    f"Session '{session_id}' not found. "
                    f"Use idalib_open to create a session first."
                )
            self.sr.touch(session_id)
            inst = self.im.find(sess.instance_index)
            if inst is None:
                raise RuntimeError(
                    f"Instance for session '{session_id}' is gone. "
                    f"The session may need to be re-opened."
                )
            if inst.closing:
                raise RuntimeError(f"Session '{session_id}' is closing.")
            if not inst.is_alive():
                raise RuntimeError(
                    f"Instance for session '{session_id}' is not running. "
                    "The session may need to be re-opened."
                )
            return sess, inst

    # ------------------------------------------------------------------
    # Context binding pass-throughs
    # ------------------------------------------------------------------

    def bind_context(self, context_id: str, session_id: str) -> None:
        with self._lock:
            self.sr.bind_context(context_id, session_id)

    def unbind_context(self, context_id: str) -> str | None:
        with self._lock:
            return self.sr.unbind_context(context_id)

    def get_context_session_id(self, context_id: str) -> str | None:
        with self._lock:
            return self.sr.get_context_session_id(context_id)

    def increment_refcount(self, session_id: str) -> int:
        with self._lock:
            return self.sr.increment_refcount(session_id)

    def decrement_refcount(self, session_id: str) -> int:
        with self._lock:
            return self.sr.decrement_refcount(session_id)

    def get_refcount(self, session_id: str) -> int:
        with self._lock:
            return self.sr.get_refcount(session_id)

    # ------------------------------------------------------------------
    # Listing
    # ------------------------------------------------------------------

    def list_sessions(self, context_id: str | None = None) -> dict:
        with self._lock:
            return self.sr.list_all(context_id=context_id)

    # ------------------------------------------------------------------
    # Forwarding shortcuts
    # ------------------------------------------------------------------

    def cancel_instance_request(self, inst: InstanceInfo, notification: dict) -> bool:
        """Deliver cancellation without waiting for the active instance lock."""
        if inst.is_external:
            if inst.ws_bridge is None or not inst.ws_bridge.alive:
                return False
            inst.ws_bridge.send_notification(notification)
            return True

        return self.im.send_control(inst, "cancel")

    def forward_tool_call(self, inst: InstanceInfo, tool_name: str, arguments: dict) -> Any:
        with self._operation():
            with inst.operation_lock:
                self._ensure_instance_forwardable(inst)
                return self.im.forward_tool_call(inst, tool_name, arguments)

    def forward_raw(self, inst: InstanceInfo, request: dict) -> dict:
        with self._operation():
            with inst.operation_lock:
                self._ensure_instance_forwardable(inst)
                return self.im.forward_raw(inst, request)

    def _ensure_instance_forwardable(self, inst: InstanceInfo) -> None:
        with self._lock:
            if inst.closing:
                raise RuntimeError(f"Instance {inst.index} is closing")
            if not self.im.contains(inst):
                raise RuntimeError(f"Instance {inst.index} is no longer registered")
        if not inst.is_alive():
            raise RuntimeError(f"Instance {inst.index} is not running")
