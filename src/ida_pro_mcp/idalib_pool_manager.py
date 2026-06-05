"""idalib Pool Manager — manages a pool of idalib_server subprocess instances.

Each instance is an independent idalib_server process communicating over a
Unix domain socket.  The pool enforces a 1-instance-per-session model: every
instance holds at most one active IDB at a time.

Key invariants
--------------
* ``SessionRegistry._open_paths`` prevents the same binary from being opened
  by two instances concurrently (IDA creates working files alongside the IDB).
* Sessions are always "hot" (backed by a running instance).  Closing a session
  kills its instance.
* Each session has a reference count tracking how many agents have it open.
  When the refcount reaches zero the session is closed automatically.
* ``_context_bindings`` maps MCP transport session IDs to IDA session IDs,
  providing per-agent routing so multiple agents sharing one MCP endpoint
  can work on different IDBs without interfering.
"""

from __future__ import annotations

import http.client
import json
import logging
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class SessionInfo:
    session_id: str
    binary_path: str
    instance_index: int
    last_accessed: float = field(default_factory=time.monotonic)

    def to_dict(self, *, refcount: int = 0) -> dict:
        return {
            "session_id": self.session_id,
            "input_path": self.binary_path,
            "filename": os.path.basename(self.binary_path),
            "refcount": refcount,
            "last_accessed": self.last_accessed,
            "instance_index": self.instance_index,
        }


@dataclass
class InstanceInfo:
    index: int
    socket_path: str
    process: subprocess.Popen
    session_id: str | None = None  # None = idle


# ---------------------------------------------------------------------------
# Instance Manager — subprocess lifecycle + HTTP forwarding
# ---------------------------------------------------------------------------

class InstanceManager:
    """Manages idalib_server subprocesses and communicates over Unix sockets."""

    def __init__(
        self,
        socket_dir: str,
        idalib_args: list[str] | None = None,
    ):
        self.socket_dir = socket_dir
        self.idalib_args = idalib_args or []
        self.instances: list[InstanceInfo] = []
        self._next_index = 0

    def spawn(self) -> InstanceInfo:
        idx = self._next_index
        sock_path = os.path.join(self.socket_dir, f"{idx}.sock")
        log_path = os.path.join(self.socket_dir, f"{idx}.log")
        cmd = [
            sys.executable, "-m", "ida_pro_mcp.idalib_server",
            "--unix-socket", sock_path,
            *self.idalib_args,
        ]
        logger.info("Spawning instance %d: %s (log: %s)", idx, " ".join(cmd), log_path)
        log_file = open(log_path, "w")
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
        inst = InstanceInfo(
            index=idx,
            socket_path=sock_path,
            process=proc,
        )
        inst._log_file = log_file  # type: ignore[attr-defined]
        self._next_index += 1
        self.instances.append(inst)
        self._wait_for_ready(inst)
        return inst

    def kill(self, inst: InstanceInfo) -> None:
        logger.info("Killing instance %d (pid %d)", inst.index, inst.process.pid)
        try:
            inst.process.send_signal(signal.SIGTERM)
            inst.process.wait(timeout=10)
        except Exception:
            inst.process.kill()
            inst.process.wait(timeout=5)
        log_file = getattr(inst, "_log_file", None)
        if log_file:
            log_file.close()
        if inst in self.instances:
            self.instances.remove(inst)

    def kill_all(self) -> None:
        for inst in list(self.instances):
            self.kill(inst)
        self.instances.clear()

    def find(self, index: int) -> InstanceInfo | None:
        for inst in self.instances:
            if inst.index == index:
                return inst
        return None

    def find_idle(self) -> InstanceInfo | None:
        for inst in self.instances:
            if inst.session_id is None:
                return inst
        return None

    def _wait_for_ready(self, inst: InstanceInfo, timeout: float = 120) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if inst.process.poll() is not None:
                raise RuntimeError(
                    f"Instance {inst.index} exited prematurely "
                    f"(code {inst.process.returncode})"
                )
            if os.path.exists(inst.socket_path):
                try:
                    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    sock.connect(inst.socket_path)
                    sock.close()
                    logger.info("Instance %d ready at %s", inst.index, inst.socket_path)
                    return
                except (ConnectionRefusedError, OSError):
                    pass
            time.sleep(0.2)
        raise TimeoutError(
            f"Instance {inst.index} did not become ready within {timeout}s"
        )

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
        conn = http.client.HTTPConnection("localhost", timeout=300)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(inst.socket_path)
        conn.sock = sock
        try:
            body = json.dumps(request)
            conn.request("POST", "/mcp", body, {"Content-Type": "application/json"})
            resp = conn.getresponse()
            data = resp.read().decode()
            if resp.status >= 400:
                raise RuntimeError(f"HTTP {resp.status}: {data}")
            return json.loads(data)
        finally:
            conn.close()

    def forward_tools_list(self) -> list[dict]:
        candidates = [i for i in self.instances if i.process.poll() is None]
        if not candidates:
            return []
        request = {"jsonrpc": "2.0", "method": "tools/list", "id": 1}
        resp = self.forward_raw(candidates[0], request)
        return resp.get("result", {}).get("tools", [])


# ---------------------------------------------------------------------------
# Session Registry — session state, path dedup, context bindings, refcounts
# ---------------------------------------------------------------------------

class SessionRegistry:
    """Tracks session metadata, path uniqueness, context bindings, and refcounts."""

    def __init__(self):
        self.sessions: dict[str, SessionInfo] = {}
        self._open_paths: dict[str, str] = {}
        self._context_bindings: dict[str, str] = {}
        self._refcounts: dict[str, int] = {}

    def create(
        self, session_id: str, binary_path: str, instance_index: int
    ) -> SessionInfo:
        sess = SessionInfo(
            session_id=session_id,
            binary_path=binary_path,
            instance_index=instance_index,
        )
        self.sessions[session_id] = sess
        self._open_paths[binary_path] = session_id
        self._refcounts[session_id] = 0
        return sess

    def remove(self, session_id: str) -> SessionInfo | None:
        """Permanently remove a session."""
        sess = self.sessions.pop(session_id, None)
        if sess:
            self._open_paths.pop(sess.binary_path, None)
        self._refcounts.pop(session_id, None)
        self._unbind_session_everywhere(session_id)
        return sess

    def get(self, session_id: str) -> SessionInfo | None:
        return self.sessions.get(session_id)

    def touch(self, session_id: str) -> None:
        sess = self.sessions.get(session_id)
        if sess:
            sess.last_accessed = time.monotonic()

    def find_by_path(self, resolved_path: str) -> str | None:
        """Return session_id if this path is already tracked."""
        return self._open_paths.get(resolved_path)

    def generate_id(self) -> str:
        return str(uuid.uuid4())[:8]

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
    def __init__(
        self,
        max_instances: int = 1,
        socket_dir: str | None = None,
        idalib_args: list[str] | None = None,
    ):
        self.max_instances = max_instances
        socket_dir = socket_dir or tempfile.mkdtemp(prefix="idalib-pool-")
        os.makedirs(socket_dir, exist_ok=True)

        self.im = InstanceManager(socket_dir, idalib_args)
        self.sr = SessionRegistry()
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # High-level operations
    # ------------------------------------------------------------------

    def spawn_instance(self) -> InstanceInfo:
        return self.im.spawn()

    def shutdown_all(self) -> None:
        with self._lock:
            instances_to_save = [
                inst for inst in self.im.instances if inst.session_id
            ]

        for inst in instances_to_save:
            try:
                self.im.forward_tool_call(inst, "idalib_save", {})
            except Exception:
                logger.warning(
                    "Failed to save instance %d (session %s), continuing shutdown",
                    inst.index, inst.session_id,
                )

        with self._lock:
            self.im.kill_all()
            self.sr.sessions.clear()
            self.sr._open_paths.clear()
            self.sr._context_bindings.clear()
            self.sr._refcounts.clear()

    def open_session(
        self,
        binary_path: str,
        session_id: str | None = None,
        run_auto_analysis: bool = True,
    ) -> dict:
        resolved = os.path.abspath(binary_path)

        with self._lock:
            existing_sid = self.sr.find_by_path(resolved)
            if existing_sid is not None:
                self.sr.touch(existing_sid)
                sess = self.sr.get(existing_sid)
                return {
                    "success": True,
                    "existing": True,
                    "session": sess.to_dict(refcount=self.sr.get_refcount(existing_sid)),
                    "message": f"Binary already open as session '{existing_sid}'.",
                }

            inst = self._allocate_instance_locked()
            if session_id is None:
                session_id = self.sr.generate_id()

        resp = self.im.forward_tool_call(inst, "idalib_open", {
            "input_path": resolved,
            "run_auto_analysis": run_auto_analysis,
            "session_id": session_id,
        })

        if isinstance(resp, dict) and resp.get("error"):
            return resp

        with self._lock:
            sess = self.sr.create(session_id, resolved, inst.index)
            inst.session_id = session_id

        return {
            "success": True,
            "existing": False,
            "session": sess.to_dict(refcount=self.sr.get_refcount(session_id)),
            "message": f"Session created: {session_id}",
        }

    def close_session(self, session_id: str) -> dict:
        with self._lock:
            sess = self.sr.get(session_id)
            if sess is None:
                return {"success": False, "error": f"Session not found: {session_id}"}
            inst = self.im.find(sess.instance_index)
            if inst is None:
                self.sr.remove(session_id)
                return {"success": True, "closed": True, "message": f"Session cleaned up: {session_id}"}

        try:
            self.im.forward_tool_call(inst, "idalib_save", {})
        except Exception:
            logger.warning("Failed to save before closing session %s", session_id)
        self.im.forward_tool_call(inst, "idalib_close", {"session_id": session_id})

        with self._lock:
            self.sr.remove(session_id)
            inst.session_id = None
            self.im.kill(inst)

        return {"success": True, "closed": True, "message": f"Session closed: {session_id}"}

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

    def forward_tool_call(self, inst: InstanceInfo, tool_name: str, arguments: dict) -> Any:
        return self.im.forward_tool_call(inst, tool_name, arguments)

    def forward_raw(self, inst: InstanceInfo, request: dict) -> dict:
        return self.im.forward_raw(inst, request)

    def forward_tools_list(self) -> list[dict]:
        with self._lock:
            return self.im.forward_tools_list()

    # ------------------------------------------------------------------
    # Instance allocation (internal, caller holds _lock)
    # ------------------------------------------------------------------

    def _allocate_instance_locked(self) -> InstanceInfo:
        inst = self.im.find_idle()
        if inst is not None:
            return inst
        self._lock.release()
        try:
            return self.im.spawn()
        finally:
            self._lock.acquire()
