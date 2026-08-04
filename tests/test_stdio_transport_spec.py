import io
import json
import logging
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout

from ida_pro_mcp import idalib_pool_server

mcp_mod = idalib_pool_server._mcp_mod
jsonrpc_mod = idalib_pool_server._jsonrpc_mod
McpServer = mcp_mod.McpServer


class StdioTransportSpecTests(unittest.TestCase):
    def _run_stdio(self, messages, *, log_level=logging.DEBUG):
        stdin = io.BytesIO(
            b"".join(
                json.dumps(message).encode("utf-8") + b"\n"
                for message in messages
            )
        )
        transport_stdout = io.BytesIO()
        process_stdout = io.StringIO()
        process_stderr = io.StringIO()

        server = McpServer("ida-pro-mcp")
        with (
            self.assertLogs("ida_mcp", level=log_level) as captured,
            redirect_stdout(process_stdout),
            redirect_stderr(process_stderr),
        ):
            server.stdio(stdin=stdin, stdout=transport_stdout)

        return (
            transport_stdout.getvalue(),
            process_stdout.getvalue(),
            process_stderr.getvalue(),
            "\n".join(captured.output),
        )

    def test_stdio_stdout_contains_only_jsonrpc_messages(self):
        transport_stdout, process_stdout, process_stderr, logs = self._run_stdio([
            {
                "jsonrpc": "2.0",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1.0"},
                },
                "id": 1,
            }
        ])

        self.assertEqual(process_stdout, "")
        self.assertEqual(process_stderr, "")
        self.assertIn(">> initialize", logs)
        self.assertIn("<< initialize", logs)

        lines = transport_stdout.decode("utf-8").splitlines()
        self.assertEqual(len(lines), 1)
        response = json.loads(lines[0])
        self.assertEqual(response["jsonrpc"], "2.0")
        self.assertEqual(response["id"], 1)
        self.assertEqual(response["result"]["protocolVersion"], "2025-11-25")

    def test_info_logging_hides_request_and_response_payloads(self):
        _transport, _stdout, stderr, logs = self._run_stdio(
            [{"jsonrpc": "2.0", "method": "ping", "id": 1}],
            log_level=logging.INFO,
        )

        self.assertEqual(stderr, "")
        self.assertIn("MCP transport session opened", logs)
        self.assertIn("MCP transport session closed", logs)
        self.assertNotIn(">> ping", logs)
        self.assertNotIn("<< ping", logs)

    def test_stdio_eof_reports_transport_session_closed(self):
        server = McpServer("ida-pro-mcp")
        closed = []
        server.transport_session_closed = (
            lambda context_id, reason: closed.append((context_id, reason))
        )

        server.stdio(stdin=io.BytesIO(), stdout=io.BytesIO())

        self.assertEqual(closed, [("stdio:default", "eof")])

    def test_transport_close_callback_waits_for_active_request(self):
        server = McpServer("ida-pro-mcp")
        closed = []
        server.transport_session_closed = (
            lambda context_id, reason: closed.append((context_id, reason))
        )
        server.open_transport_session("http:test")
        self.assertTrue(server.begin_transport_request("http:test"))

        self.assertTrue(
            server.terminate_transport_session("http:test", "client_terminated")
        )
        self.assertFalse(
            server.terminate_transport_session("http:test", "server_stopped")
        )
        self.assertEqual(closed, [])

        server.end_transport_request("http:test")

        self.assertEqual(closed, [("http:test", "client_terminated")])

    def test_stdio_cancel_notification_logs_at_debug(self):
        jsonrpc_mod.register_pending_request("req-1", "stdio:default")
        try:
            transport_stdout, process_stdout, process_stderr, logs = self._run_stdio([
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/cancelled",
                    "params": {
                        "requestId": "req-1",
                        "reason": "test",
                    },
                }
            ])
        finally:
            jsonrpc_mod.unregister_pending_request("req-1", "stdio:default")

        self.assertEqual(transport_stdout, b"")
        self.assertEqual(process_stdout, "")
        self.assertEqual(process_stderr, "")
        self.assertIn("Cancelled request req-1", logs)

    def test_pending_request_ids_are_isolated_by_transport_context(self):
        first = jsonrpc_mod.register_pending_request(1, "http:first")
        second = jsonrpc_mod.register_pending_request(1, "http:second")
        try:
            self.assertTrue(jsonrpc_mod.cancel_request(1, "http:first"))
            self.assertTrue(first.is_set())
            self.assertFalse(second.is_set())
        finally:
            jsonrpc_mod.unregister_pending_request(1, "http:first")
            jsonrpc_mod.unregister_pending_request(1, "http:second")

    def test_stdio_reads_cancellation_while_tool_is_running(self):
        started = threading.Event()
        server = McpServer("ida-pro-mcp")

        @server.tool
        def wait_for_cancel() -> dict:
            cancel_event = jsonrpc_mod.get_current_cancel_event()
            started.set()
            if cancel_event is not None and cancel_event.wait(2):
                raise jsonrpc_mod.RequestCancelledError("cancelled by test")
            return {"cancelled": False}

        messages = [
            {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": "wait_for_cancel", "arguments": {}},
                "id": 7,
            },
            {
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": {"requestId": 7, "reason": "test"},
            },
        ]

        class CoordinatedInput:
            def __init__(self):
                self.index = 0

            def readline(self):
                if self.index >= len(messages):
                    return b""
                if self.index == 1:
                    if not started.wait(2):
                        raise AssertionError("tool did not start")
                message = messages[self.index]
                self.index += 1
                return json.dumps(message).encode("utf-8") + b"\n"

        stdout = io.BytesIO()
        server.stdio(stdin=CoordinatedInput(), stdout=stdout)

        response = json.loads(stdout.getvalue())
        self.assertEqual(response["id"], 7)
        self.assertTrue(response["result"]["isError"])
        self.assertIn("cancelled by test", response["result"]["content"][0]["text"])


if __name__ == "__main__":
    unittest.main()
