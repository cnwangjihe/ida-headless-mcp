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
from typing import Any

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
        self._request_queue: queue.Queue[dict] = queue.Queue()
        self._response_queue: queue.Queue[dict] = queue.Queue()
        self._request_event = threading.Event()
        self._agent_count_response: queue.Queue[dict] = queue.Queue()

    def forward_request(self, request: dict, timeout: float = 300) -> dict:
        """Send a JSON-RPC request to the plugin and return the response.

        Called by routing threads. Serialized by ``forward_lock`` since
        the plugin (IDA) processes one call at a time.
        """
        if not self.alive:
            raise ConnectionError("External instance disconnected")
        with self.forward_lock:
            self._request_queue.put(request)
            self._request_event.set()
            try:
                return self._response_queue.get(timeout=timeout)
            except queue.Empty:
                raise TimeoutError(
                    "External instance did not respond within "
                    f"{timeout}s"
                )

    def send_agent_count(self, count: int) -> None:
        """Send an agent_count response to the plugin (called from handler)."""
        try:
            self.ws.send(json.dumps({
                "type": "agent_count",
                "active_agents": count,
            }))
        except Exception:
            self.alive = False

    def run_loop(self, on_check_agents=None):
        """Main loop for the handler thread.

        Reads from the plugin WebSocket and processes pending forward
        requests from routing threads.

        Args:
            on_check_agents: callback(session_id) → int returning agent count
        """
        try:
            while self.alive:
                # Wait for a forward request or timeout for housekeeping
                self._request_event.wait(timeout=30)
                self._request_event.clear()

                # Process all pending forward requests
                while not self._request_queue.empty():
                    try:
                        request = self._request_queue.get_nowait()
                    except queue.Empty:
                        break
                    try:
                        self.ws.send(json.dumps(request))
                        raw = self.ws.recv()
                        response = json.loads(raw)
                        self._response_queue.put(response)
                    except Exception as e:
                        logger.warning("Forward to external instance failed: %s", e)
                        self._response_queue.put({
                            "jsonrpc": "2.0",
                            "error": {"code": -32000, "message": f"External instance error: {e}"},
                            "id": request.get("id"),
                        })
                        self.alive = False
                        return

                # Check for unsolicited messages from plugin
                # (e.g., check_agents request)
                try:
                    self.ws.socket.settimeout(0.1)
                    raw = self.ws.recv()
                    msg = json.loads(raw)
                    if msg.get("type") == "check_agents" and on_check_agents:
                        count = on_check_agents()
                        self.send_agent_count(count)
                except TimeoutError:
                    pass
                except Exception:
                    pass
                finally:
                    try:
                        self.ws.socket.settimeout(None)
                    except Exception:
                        pass

        except Exception as e:
            logger.info("External instance bridge loop ended: %s", e)
        finally:
            self.alive = False
