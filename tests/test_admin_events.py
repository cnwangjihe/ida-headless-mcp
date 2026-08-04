import unittest
from unittest.mock import MagicMock

from ida_pro_mcp import idalib_pool_server
from ida_pro_mcp.idalib_pool_manager import (
    InstanceInfo,
    InstanceManager,
    PoolManager,
)


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


class PoolAdministrationEventTests(unittest.TestCase):
    def _make_pool(self):
        pool = PoolManager(runtime_dir="/tmp/fake-pool")
        pool.im = MagicMock(spec=InstanceManager)
        pool.im.instances = []
        pool.im.snapshot.side_effect = lambda: list(pool.im.instances)
        pool.im.contains.side_effect = lambda inst: inst in pool.im.instances
        pool.admin_event_sink = self.events.append
        return pool

    def setUp(self):
        self.events = []

    def test_acquire_and_release_context_emit_complete_relationships(self):
        pool = self._make_pool()
        process = MagicMock()
        process.is_alive.return_value = True
        process.pid = 4242
        inst = InstanceInfo(
            0,
            process,
            session_id="s1",
            log_path="/tmp/fake-pool/0.log",
        )
        pool.im.find.return_value = inst
        pool.im.forward_tool_call.return_value = {"success": True}
        pool.sr.create("s1", "/tmp/a.elf", "/tmp/a.i64", 0)

        pool.acquire_session("http:agent-a", "s1", bind=True)

        self.assertEqual(
            [event.kind for event in self.events],
            ["IdbActivityChanged", "ContextMappingChanged"],
        )
        idb = self.events[0].payload
        self.assertEqual(idb["holder_context_ids"], ["http:agent-a"])
        self.assertEqual(idb["refcount"], 1)
        self.assertEqual(idb["pid"], 4242)
        self.assertEqual(idb["log_path"], "/tmp/fake-pool/0.log")
        context = self.events[1].payload
        self.assertEqual(context["bound_session_id"], "s1")
        self.assertEqual(context["held_session_ids"], ["s1"])

        self.events.clear()
        result = pool.release_context("http:agent-a")

        self.assertTrue(result["success"])
        self.assertEqual(
            [event.kind for event in self.events],
            ["ContextMappingChanged", "IdbClosing", "IdbClosed"],
        )
        self.assertEqual(self.events[0].payload["held_session_ids"], [])
        self.assertEqual(self.events[1].payload["refcount"], 0)
        self.assertEqual(self.events[-1].payload["state"], "CLOSED")

    def test_open_and_reuse_emit_idb_and_context_updates(self):
        pool = self._make_pool()
        process = MagicMock()
        process.is_alive.return_value = True
        inst = InstanceInfo(0, process)
        pool.im.spawn.return_value = inst
        pool.im.find.return_value = inst
        pool.im.forward_tool_call.return_value = {
            "success": True,
            "session": {
                "input_path": "/tmp/a.elf",
                "idb_path": "/tmp/a.i64",
            },
        }

        first = pool.open_session("/tmp/a.elf", context_id="http:agent-a")

        self.assertTrue(first["success"])
        self.assertEqual(
            [event.kind for event in self.events],
            [
                "IdbOpenStarted",
                "IdbOpened",
                "ContextMappingChanged",
                "IdbOpenFinished",
            ],
        )
        session_id = first["session"]["session_id"]
        operation_id = self.events[0].entity_id
        self.assertEqual(self.events[0].payload["context_id"], "http:agent-a")
        self.assertEqual(self.events[0].payload["input_path"], "/tmp/a.elf")
        self.assertEqual(self.events[1].entity_id, session_id)
        self.assertEqual(self.events[1].payload["refcount"], 1)
        self.assertEqual(self.events[-1].entity_id, operation_id)
        self.assertTrue(self.events[-1].payload["success"])
        self.assertEqual(self.events[-1].payload["session_id"], session_id)

        self.events.clear()
        reused = pool.open_session("/tmp/a.elf", context_id="http:agent-a")

        self.assertTrue(reused["existing"])
        self.assertEqual(
            [event.kind for event in self.events],
            [
                "IdbOpenStarted",
                "IdbActivityChanged",
                "ContextMappingChanged",
                "IdbOpenFinished",
            ],
        )

    def test_failed_open_finishes_the_opening_lifecycle(self):
        pool = self._make_pool()
        process = MagicMock()
        process.is_alive.return_value = True
        inst = InstanceInfo(0, process)
        pool.im.spawn.return_value = inst
        pool.im.find.return_value = inst
        pool.im.forward_tool_call.return_value = {"error": "invalid IDB"}

        result = pool.open_session(
            "/tmp/broken.i64",
            context_id="http:agent-a",
        )

        self.assertFalse(result.get("success", False))
        self.assertEqual(
            [event.kind for event in self.events],
            ["IdbOpenStarted", "IdbOpenFinished"],
        )
        self.assertEqual(self.events[0].entity_id, self.events[1].entity_id)
        self.assertFalse(self.events[1].payload["success"])
        self.assertEqual(self.events[1].payload["error"], "invalid IDB")

    def test_force_close_emits_one_batch_of_cleared_contexts(self):
        pool = self._make_pool()
        process = MagicMock()
        process.is_alive.return_value = True
        inst = InstanceInfo(0, process, session_id="s1")
        pool.im.find.return_value = inst
        pool.im.forward_tool_call.return_value = {"success": True}
        pool.sr.create("s1", "/tmp/a.elf", "/tmp/a.i64", 0)
        for context_id in ("http:agent-a", "http:agent-b"):
            pool.sr.acquire_context_session(context_id, "s1")
            pool.sr.bind_context(context_id, "s1")

        result = pool.close_session("s1")

        self.assertTrue(result["success"])
        self.assertEqual(
            [event.kind for event in self.events],
            [
                "IdbClosing",
                "ContextMappingChanged",
                "ContextMappingChanged",
                "IdbClosed",
            ],
        )
        context_events = self.events[1:3]
        self.assertEqual(
            {event.entity_id for event in context_events},
            {"http:agent-a", "http:agent-b"},
        )
        self.assertTrue(
            all(event.payload["held_session_ids"] == [] for event in context_events)
        )

    def test_external_registration_and_unregistration_emit_owner_state(self):
        pool = PoolManager(runtime_dir="/tmp/fake-pool")
        pool.admin_event_sink = self.events.append
        bridge = MagicMock()
        bridge.alive = True

        result = pool.register_external(
            bridge, "/tmp/gui.elf", "/tmp/gui.i64"
        )
        session_id = result["session"]["session_id"]

        self.assertEqual(self.events[-1].kind, "ExternalIdbRegistered")
        self.assertTrue(self.events[-1].payload["is_external"])
        self.assertEqual(self.events[-1].payload["refcount"], 1)

        pool.sr.acquire_context_session("http:agent-a", session_id)
        pool.sr.bind_context("http:agent-a", session_id)
        self.events.clear()
        result = pool.unregister_external(session_id)

        self.assertTrue(result["success"])
        self.assertEqual(
            [event.kind for event in self.events],
            ["ExternalIdbUnregistered", "ContextMappingChanged"],
        )
        self.assertEqual(self.events[0].payload["state"], "CLOSED")
        self.assertEqual(self.events[1].payload["held_session_ids"], [])


class PoolAdministrationSaveTests(unittest.TestCase):
    def _make_session(self, *, external=False):
        pool = PoolManager(runtime_dir="/tmp/fake-pool")
        pool.im = MagicMock(spec=InstanceManager)
        if external:
            bridge = MagicMock()
            bridge.alive = True
            inst = InstanceInfo(
                0,
                None,
                session_id="s1",
                ws_bridge=bridge,
            )
        else:
            process = MagicMock()
            process.is_alive.return_value = True
            inst = InstanceInfo(0, process, session_id="s1")
        pool.im.find.return_value = inst
        pool.sr.create(
            "s1",
            "/tmp/a.elf",
            "/tmp/a.i64",
            0,
            is_external=external,
        )
        pool.sr.acquire_context_session("http:agent-a", "s1")
        pool.sr.bind_context("http:agent-a", "s1")
        return pool, inst

    def test_save_local_session_preserves_context_lease(self):
        pool, inst = self._make_session()
        events = []
        pool.admin_event_sink = events.append
        pool.im.forward_tool_call.return_value = {
            "ok": True,
            "path": "/tmp/a.i64",
            "error": None,
        }

        result = pool.save_session("s1")

        self.assertTrue(result["success"])
        pool.im.forward_tool_call.assert_called_once_with(
            inst, "idalib_save", {}
        )
        self.assertEqual(pool.get_refcount("s1"), 1)
        self.assertEqual(pool.get_context_session_id("http:agent-a"), "s1")
        self.assertEqual([event.kind for event in events], ["IdbActivityChanged"])

    def test_save_external_session_uses_same_operation_without_new_ref(self):
        pool, inst = self._make_session(external=True)
        pool.im.forward_tool_call.return_value = {
            "ok": True,
            "path": "/tmp/a.i64",
            "error": None,
        }

        result = pool.save_session("s1")

        self.assertTrue(result["success"])
        pool.im.forward_tool_call.assert_called_once_with(
            inst, "idalib_save", {}
        )
        self.assertEqual(pool.get_refcount("s1"), 2)

    def test_save_failure_is_returned_without_touching_relationships(self):
        pool, _inst = self._make_session()
        original_access = pool.sr.get("s1").last_accessed
        pool.im.forward_tool_call.return_value = {
            "ok": False,
            "path": "/tmp/a.i64",
            "error": "disk full",
        }

        result = pool.save_session("s1")

        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "disk full")
        self.assertEqual(pool.sr.get("s1").last_accessed, original_access)
        self.assertEqual(pool.get_refcount("s1"), 1)


if __name__ == "__main__":
    unittest.main()
