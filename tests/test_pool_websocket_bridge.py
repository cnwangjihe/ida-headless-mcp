import json
import queue
import threading
import unittest

from ida_pro_mcp.pool_websocket import ExternalInstanceBridge


class _FakeWebSocket:
    def __init__(self, incoming, auto_responses=None):
        self.incoming = queue.Queue()
        for msg in incoming:
            if isinstance(msg, str):
                self.incoming.put(msg)
            else:
                self.incoming.put(json.dumps(msg))
        self.sent = []
        self.auto_responses = auto_responses or {}

    def send(self, data):
        msg = json.loads(data)
        self.sent.append(msg)
        response = self.auto_responses.get(msg.get("id"))
        if response is not None:
            self.incoming.put(json.dumps(response))

    def recv(self, timeout=None):
        try:
            if timeout is None:
                return self.incoming.get(timeout=2)
            return self.incoming.get(timeout=timeout)
        except queue.Empty:
            raise TimeoutError()


class TestExternalInstanceBridge(unittest.TestCase):
    def test_control_message_during_forward_does_not_replace_response(self):
        ws = _FakeWebSocket(
            [
                {"type": "check_agents"},
                {"jsonrpc": "2.0", "result": {"ok": True}, "id": 7},
            ]
        )
        bridge = ExternalInstanceBridge(ws)
        thread = threading.Thread(
            target=bridge.run_loop,
            kwargs={"on_check_agents": lambda: 2},
            daemon=True,
        )
        thread.start()
        self.addCleanup(lambda: setattr(bridge, "alive", False))

        response = bridge.forward_request(
            {"jsonrpc": "2.0", "method": "tools/list", "id": 7},
            timeout=2,
        )

        self.assertEqual(response, {"jsonrpc": "2.0", "result": {"ok": True}, "id": 7})
        self.assertEqual(ws.sent[0], {"jsonrpc": "2.0", "method": "tools/list", "id": 7})
        self.assertEqual(ws.sent[1], {"type": "agent_count", "active_agents": 2})

    def test_bad_response_returns_error_without_disconnect(self):
        ws = _FakeWebSocket(
            [
                "{not-json",
            ],
            auto_responses={
                8: {"jsonrpc": "2.0", "result": {"ok": True}, "id": 8},
            },
        )
        bridge = ExternalInstanceBridge(ws)
        thread = threading.Thread(target=bridge.run_loop, daemon=True)
        thread.start()
        self.addCleanup(lambda: setattr(bridge, "alive", False))

        first = bridge.forward_request(
            {"jsonrpc": "2.0", "method": "tools/call", "id": 7},
            timeout=2,
        )
        self.assertEqual(first["jsonrpc"], "2.0")
        self.assertEqual(first["id"], 7)
        self.assertIn("error", first)
        self.assertTrue(bridge.alive)

        second = bridge.forward_request(
            {"jsonrpc": "2.0", "method": "tools/list", "id": 8},
            timeout=2,
        )
        self.assertEqual(second, {"jsonrpc": "2.0", "result": {"ok": True}, "id": 8})


if __name__ == "__main__":
    unittest.main()
