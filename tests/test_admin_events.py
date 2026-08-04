import unittest
from unittest.mock import MagicMock

from ida_pro_mcp import idalib_pool_server


McpServer = idalib_pool_server._mcp_mod.McpServer
McpSseConnection = idalib_pool_server._mcp_mod._McpSseConnection


class TransportAdministrationEventTests(unittest.TestCase):
    def setUp(self):
        self.server = McpServer("test")
        self.events = []
        self.server.admin_event_sink = self.events.append

    def test_transport_lifecycle_emits_incremental_state(self):
        context_id = "http:agent-a"
        self.server.open_transport_session(context_id, peer="127.0.0.1:1234")
        self.assertTrue(self.server.begin_transport_request(context_id))

        self.server._transport_session_id.data = context_id
        try:
            self.server._mcp_initialize(
                "2025-11-25",
                {},
                {"name": "codex", "version": "1.2.3"},
            )
        finally:
            self.server._transport_session_id.data = None

        self.server.end_transport_request(context_id)
        self.server.terminate_transport_session(context_id, "client_terminated")

        self.assertEqual(
            [event.kind for event in self.events],
            [
                "TransportOpened",
                "TransportActivityChanged",
                "TransportClientUpdated",
                "TransportActivityChanged",
                "TransportClosing",
                "TransportClosed",
            ],
        )
        revisions = [event.revision for event in self.events]
        self.assertEqual(revisions, sorted(revisions))
        self.assertEqual(len(revisions), len(set(revisions)))

        client_event = self.events[2]
        self.assertEqual(client_event.entity_id, context_id)
        self.assertEqual(client_event.payload["client_name"], "codex")
        self.assertEqual(client_event.payload["peer"], "127.0.0.1:1234")

        closing_event = self.events[-2]
        self.assertEqual(closing_event.payload["state"], "CLOSING")
        self.assertEqual(
            closing_event.payload["closing_reason"], "client_terminated"
        )
        self.assertEqual(self.events[-1].payload["reason"], "client_terminated")

    def test_closing_remains_visible_until_active_request_finishes(self):
        context_id = "sse:agent-b"
        callback_state = []
        self.server.transport_session_closed = lambda context, reason: (
            callback_state.append(
                (
                    context,
                    reason,
                    context in self.server._open_transport_sessions,
                    self.server._transport_closing.get(context),
                )
            )
        )

        self.server.open_transport_session(context_id)
        self.server.begin_transport_request(context_id)
        self.assertTrue(
            self.server.terminate_transport_session(context_id, "disconnect")
        )

        self.assertEqual(self.events[-1].kind, "TransportClosing")
        self.assertEqual(self.events[-1].payload["active_requests"], 1)
        self.assertEqual(callback_state, [])

        self.server.end_transport_request(context_id)

        self.assertEqual(
            callback_state,
            [(context_id, "disconnect", True, "disconnect")],
        )
        self.assertEqual(self.events[-1].kind, "TransportClosed")
        self.assertNotIn(context_id, self.server._open_transport_sessions)

    def test_event_sink_failure_does_not_break_transport(self):
        def broken_sink(_event):
            raise RuntimeError("broken observer")

        self.server.admin_event_sink = broken_sink
        with self.assertLogs("ida_mcp.transport", level="ERROR"):
            self.server.open_transport_session("http:agent-c")
            self.assertTrue(self.server.begin_transport_request("http:agent-c"))
            self.server.end_transport_request("http:agent-c")
            self.assertTrue(
                self.server.terminate_transport_session(
                    "http:agent-c", "client_terminated"
                )
            )


class TransportAdministrationDisconnectTests(unittest.TestCase):
    def setUp(self):
        self.server = McpServer("test")
        self.events = []
        self.closed = []
        self.server.admin_event_sink = self.events.append
        self.server.transport_session_closed = (
            lambda context_id, reason: self.closed.append((context_id, reason))
        )

    def test_disconnect_http_invalidates_session_and_drains_active_request(self):
        context_id = "http:agent-a"
        self.server.register_http_session("agent-a")
        self.server.begin_transport_request(context_id)

        result = self.server.disconnect_transport_session(context_id)

        self.assertEqual(
            result,
            {
                "success": True,
                "context_id": context_id,
                "state": "CLOSING",
                "active_requests": 1,
            },
        )
        self.assertFalse(self.server.has_http_session("agent-a"))
        self.assertFalse(self.server.begin_transport_request(context_id))
        self.assertEqual(self.closed, [])
        self.assertEqual(self.events[-1].kind, "TransportClosing")
        self.assertEqual(
            self.events[-1].payload["closing_reason"], "admin_disconnected"
        )

        self.server.end_transport_request(context_id)

        self.assertEqual(
            self.closed,
            [(context_id, "admin_disconnected")],
        )
        self.assertEqual(self.events[-1].kind, "TransportClosed")

    def test_disconnect_sse_shuts_down_stream_socket(self):
        connection = MagicMock()
        sse = McpSseConnection(MagicMock(), connection)
        sse.session_id = "agent-b"
        context_id = "sse:agent-b"
        self.server.open_transport_session(context_id)
        self.server._sse_connections["agent-b"] = sse

        result = self.server.disconnect_transport_session(context_id)

        self.assertTrue(result["success"])
        self.assertFalse(sse.alive)
        connection.shutdown.assert_called_once_with(
            idalib_pool_server._mcp_mod.socket.SHUT_RDWR
        )
        self.assertNotIn("agent-b", self.server._sse_connections)
        self.assertEqual(
            self.closed,
            [(context_id, "admin_disconnected")],
        )

    def test_disconnect_rejects_unknown_and_stdio_sessions(self):
        self.assertFalse(
            self.server.disconnect_transport_session("http:missing")["success"]
        )
        self.server.open_transport_session("stdio:default")
        result = self.server.disconnect_transport_session("stdio:default")
        self.assertFalse(result["success"])
        self.assertIn("Only HTTP and SSE", result["error"])


if __name__ == "__main__":
    unittest.main()
