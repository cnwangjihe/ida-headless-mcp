"""WebSocket bridge for external IDA Pro plugin ↔ pool communication.

The pool server accepts WebSocket connections from GUI IDA plugins.
Each connection registers the plugin as an external instance and
forwards JSON-RPC tool calls through the WebSocket.

Thread model: the WebSocket handler thread owns all socket I/O.
Routing threads (handling agent tool calls) communicate via a
request/response queue pair protected by ``forward_lock``.
"""

from __future__ import annotations

import json
import logging
import queue
import threading
import time

logger = logging.getLogger(__name__)


class ExternalInstanceBridge:
    """Wraps a server-side WebSocket connection for pool↔plugin forwarding.

    The handler thread calls :meth:`run_loop` which reads messages from
    the plugin and dispatches control messages.  Routing threads call
    :meth:`forward_request` to send a JSON-RPC request and wait for
    the response.
    """

    def __init__(self, ws):
        self.ws = ws
        self.alive = True
        self.forward_lock = threading.Lock()
        self._request_queue: queue.Queue[
            tuple[dict, dict, float, queue.Queue[dict]]
        ] = queue.Queue()
        self._notification_queue: queue.Queue[dict] = queue.Queue()
        self._request_event = threading.Event()
        self._next_request_id = 1

    def forward_request(self, request: dict, timeout: float = 300) -> dict:
        """Send a JSON-RPC request to the plugin and return the response.

        Called by routing threads. Serialized by ``forward_lock`` since
        the plugin (IDA) processes one call at a time.
        """
        if not self.alive:
            raise ConnectionError("External instance disconnected")
        if "id" not in request:
            raise ValueError("forward_request requires a JSON-RPC request id")

        with self.forward_lock:
            if not self.alive:
                raise ConnectionError("External instance disconnected")

            deadline = time.monotonic() + timeout
            response_queue: queue.Queue[dict] = queue.Queue(maxsize=1)
            wire_request = dict(request)
            wire_request["id"] = f"pool-{self._next_request_id}"
            self._next_request_id += 1
            self._request_queue.put(
                (request, wire_request, deadline, response_queue)
            )
            self._request_event.set()

            remaining = max(0.0, deadline - time.monotonic())
            try:
                return response_queue.get(timeout=remaining)
            except queue.Empty:
                raise TimeoutError(
                    "External instance did not respond within "
                    f"{timeout}s"
                )

    def send_notification(self, notification: dict) -> None:
        """Queue a JSON-RPC notification for the socket-owning handler thread."""
        if not self.alive:
            raise ConnectionError("External instance disconnected")
        self._notification_queue.put(dict(notification))
        self._request_event.set()

    def _send_pending_notifications(self) -> None:
        while True:
            try:
                notification = self._notification_queue.get_nowait()
            except queue.Empty:
                return
            self.ws.send(json.dumps(notification))

    def send_agent_count(self, count: int) -> None:
        """Send an agent_count response to the plugin (called from handler)."""
        try:
            self.ws.send(json.dumps({
                "type": "agent_count",
                "active_agents": count,
            }))
        except Exception:
            self.alive = False

    def _handle_control_message(self, msg: dict, on_check_agents=None) -> bool:
        """Handle plugin-side control messages.

        Returns True if the message was consumed and isn't a JSON-RPC response.
        """
        if msg.get("type") == "check_agents" and on_check_agents:
            count = on_check_agents()
            self.send_agent_count(count)
            return True
        return False

    def _jsonrpc_error(self, request: dict, message: str) -> dict:
        return {
            "jsonrpc": "2.0",
            "error": {"code": -32000, "message": message},
            "id": request.get("id"),
        }

    def _recv_jsonrpc_response(
        self,
        request: dict,
        on_check_agents=None,
        deadline: float | None = None,
    ) -> dict:
        """Read until the JSON-RPC response for ``request`` is received."""
        expected_id = request.get("id")
        while self.alive:
            timeout = None
            if deadline is not None:
                timeout = max(0.0, deadline - time.monotonic())
                if timeout == 0:
                    return self._jsonrpc_error(
                        request,
                        "External instance did not respond before the deadline",
                    )
                timeout = min(timeout, 0.1)
            try:
                raw = self.ws.recv(timeout=timeout)
            except TimeoutError:
                self._send_pending_notifications()
                if deadline is not None and time.monotonic() < deadline:
                    continue
                return self._jsonrpc_error(
                    request,
                    "External instance did not respond before the deadline",
                )
            try:
                msg = json.loads(raw)
            except (json.JSONDecodeError, TypeError) as e:
                return self._jsonrpc_error(
                    request,
                    f"External instance returned invalid JSON: {e}",
                )
            if not isinstance(msg, dict):
                return self._jsonrpc_error(
                    request,
                    "External instance returned a non-object JSON-RPC response",
                )
            if self._handle_control_message(msg, on_check_agents):
                continue
            if msg.get("jsonrpc") != "2.0":
                logger.warning(
                    "Ignoring non-JSON-RPC message from external instance: %s",
                    msg,
                )
                continue
            if expected_id is not None and msg.get("id") != expected_id:
                logger.warning(
                    "Ignoring JSON-RPC response with unexpected id %r "
                    "(expected %r)",
                    msg.get("id"),
                    expected_id,
                )
                continue
            return msg
        raise ConnectionError("External instance disconnected")

    def run_loop(self, on_check_agents=None):
        """Main loop for the handler thread.

        Reads from the plugin WebSocket and processes pending forward
        requests from routing threads.

        Args:
            on_check_agents: callback(session_id) → int returning agent count
        """
        try:
            while self.alive:
                # Also poll for unsolicited plugin messages such as check_agents.
                self._request_event.wait(timeout=0.1)
                self._request_event.clear()
                self._send_pending_notifications()

                # Process all pending forward requests
                while not self._request_queue.empty():
                    try:
                        original_request, request, deadline, response_queue = (
                            self._request_queue.get_nowait()
                        )
                    except queue.Empty:
                        break
                    try:
                        self.ws.send(json.dumps(request))
                        response = self._recv_jsonrpc_response(
                            request, on_check_agents, deadline
                        )
                        response = dict(response)
                        response["id"] = original_request.get("id")
                        response_queue.put(response)
                    except Exception as e:
                        logger.warning("Forward to external instance failed: %s", e)
                        response_queue.put(
                            self._jsonrpc_error(
                                original_request,
                                f"External instance connection error: {e}",
                            )
                        )
                        self.alive = False
                        return

                # Check for unsolicited messages from plugin
                # (e.g., check_agents request)
                try:
                    raw = self.ws.recv(timeout=0.1)
                    msg = json.loads(raw)
                    if isinstance(msg, dict):
                        self._handle_control_message(msg, on_check_agents)
                except TimeoutError:
                    pass
                except Exception as e:
                    logger.info("External instance disconnected: %s", e)
                    self.alive = False

        except Exception as e:
            logger.info("External instance bridge loop ended: %s", e)
        finally:
            self.alive = False
