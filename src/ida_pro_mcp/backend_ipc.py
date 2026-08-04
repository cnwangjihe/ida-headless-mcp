"""Cross-platform IPC primitives for pool-owned backend processes.

The transport is deliberately expressed only in terms of
``multiprocessing.Connection``.  The multiprocessing spawn context selects
the native implementation for the current platform, so callers never need to
manage Unix-socket paths, Windows named-pipe names, or TCP ports.
"""

from __future__ import annotations

import json
import logging
import threading
from collections.abc import Callable
from multiprocessing.connection import wait
from typing import Any, Protocol

logger = logging.getLogger("ida_mcp.backend.ipc")

IPC_PROTOCOL_VERSION = 1


class ConnectionLike(Protocol):
    """Common surface of POSIX Connection and Windows PipeConnection."""

    def send_bytes(self, buf: bytes) -> None: ...

    def recv_bytes(self, maxlength: int | None = None) -> bytes: ...

    def poll(self, timeout: float = 0.0) -> bool: ...


class BackendIpcError(RuntimeError):
    """Base class for backend IPC failures."""


class BackendProtocolError(BackendIpcError):
    """Raised when a peer sends a malformed or unexpected message."""


class BackendChannelClosed(BackendIpcError):
    """Raised when the peer closes its end of a connection."""


class BackendProcessExited(BackendIpcError):
    """Raised when the backend process exits before producing a message."""


def make_message(message_type: str, **fields: Any) -> dict[str, Any]:
    return {
        "type": message_type,
        "protocol": IPC_PROTOCOL_VERSION,
        **fields,
    }


def send_message(connection: ConnectionLike, message: dict[str, Any]) -> None:
    """Serialize one protocol message without using pickle."""
    if not isinstance(message, dict):
        raise TypeError("backend IPC messages must be dictionaries")
    payload = json.dumps(
        message,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    connection.send_bytes(payload)


def receive_message(connection: ConnectionLike) -> dict[str, Any]:
    """Receive and validate one protocol message."""
    try:
        raw = connection.recv_bytes()
    except EOFError as e:
        raise BackendChannelClosed("backend IPC channel closed") from e
    try:
        message = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise BackendProtocolError("backend IPC message is not valid JSON") from e
    if not isinstance(message, dict):
        raise BackendProtocolError("backend IPC message must be a JSON object")
    if message.get("protocol") != IPC_PROTOCOL_VERSION:
        raise BackendProtocolError(
            f"unsupported backend IPC protocol: {message.get('protocol')!r}"
        )
    if not isinstance(message.get("type"), str):
        raise BackendProtocolError("backend IPC message has no valid type")
    return message


def wait_for_message(
    connection: ConnectionLike,
    process_sentinel: Any,
    timeout: float,
) -> dict[str, Any]:
    """Wait for a message or process exit using one cross-platform primitive."""
    ready = wait([connection, process_sentinel], timeout=timeout)
    if connection in ready:
        try:
            return receive_message(connection)
        except BackendChannelClosed as e:
            raise BackendProcessExited("backend process closed its IPC channel") from e
    if process_sentinel in ready:
        raise BackendProcessExited("backend process exited")
    raise TimeoutError(f"backend IPC timed out after {timeout}s")


class BackendIpcServer:
    """Serve serialized RPC requests plus an independent control channel."""

    def __init__(
        self,
        rpc_connection: ConnectionLike,
        control_connection: ConnectionLike,
        dispatch: Callable[[dict[str, Any]], dict[str, Any] | None],
        cancel_pending: Callable[[], int],
    ):
        self.rpc_connection = rpc_connection
        self.control_connection = control_connection
        self.dispatch = dispatch
        self.cancel_pending = cancel_pending
        self.shutdown_requested = threading.Event()

    def serve(self, *, ready_fields: dict[str, Any] | None = None) -> None:
        control_thread = threading.Thread(
            target=self._control_loop,
            name="backend-ipc-control",
            daemon=True,
        )
        control_thread.start()
        send_message(
            self.rpc_connection,
            make_message("ready", **(ready_fields or {})),
        )

        try:
            while not self.shutdown_requested.is_set():
                if not self.rpc_connection.poll(0.1):
                    continue
                try:
                    message = receive_message(self.rpc_connection)
                except BackendChannelClosed:
                    self._request_shutdown()
                    break
                if message["type"] != "request":
                    send_message(
                        self.rpc_connection,
                        make_message(
                            "error",
                            error=f"unexpected RPC message: {message['type']}",
                        ),
                    )
                    continue
                request = message.get("payload")
                if not isinstance(request, dict):
                    send_message(
                        self.rpc_connection,
                        make_message("error", error="RPC payload must be an object"),
                    )
                    continue
                try:
                    response = self.dispatch(request)
                    send_message(
                        self.rpc_connection,
                        make_message("response", payload=response),
                    )
                except Exception as e:
                    logger.exception("Backend RPC dispatch failed")
                    send_message(
                        self.rpc_connection,
                        make_message("error", error=str(e)),
                    )
        finally:
            self.shutdown_requested.set()

    def _control_loop(self) -> None:
        while not self.shutdown_requested.is_set():
            try:
                message = receive_message(self.control_connection)
            except (BackendIpcError, OSError, ValueError):
                self._request_shutdown()
                return
            message_type = message["type"]
            if message_type == "cancel":
                self._cancel_pending()
            elif message_type == "shutdown":
                self._request_shutdown()
                return
            else:
                logger.warning(
                    "Ignoring unknown backend control message: %s",
                    message_type,
                )

    def _cancel_pending(self) -> None:
        try:
            cancelled = self.cancel_pending()
            logger.debug("Cancelled %d pending backend request(s)", cancelled)
        except Exception:
            logger.exception("Failed to cancel pending backend requests")

    def _request_shutdown(self) -> None:
        if self.shutdown_requested.is_set():
            return
        self.shutdown_requested.set()
        self._cancel_pending()
