import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout

from ida_pro_mcp import idalib_pool_server

mcp_mod = idalib_pool_server._mcp_mod
jsonrpc_mod = idalib_pool_server._jsonrpc_mod
McpServer = mcp_mod.McpServer


class StdioTransportSpecTests(unittest.TestCase):
    def setUp(self):
        self._log_requests = jsonrpc_mod._LOG_REQUESTS
        jsonrpc_mod._LOG_REQUESTS = True

    def tearDown(self):
        jsonrpc_mod._LOG_REQUESTS = self._log_requests

    def _run_stdio(self, messages):
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
        with redirect_stdout(process_stdout), redirect_stderr(process_stderr):
            server.stdio(stdin=stdin, stdout=transport_stdout)

        return (
            transport_stdout.getvalue(),
            process_stdout.getvalue(),
            process_stderr.getvalue(),
        )

    def test_stdio_stdout_contains_only_jsonrpc_messages(self):
        transport_stdout, process_stdout, process_stderr = self._run_stdio([
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
        self.assertIn("[MCP] >> initialize", process_stderr)

        lines = transport_stdout.decode("utf-8").splitlines()
        self.assertEqual(len(lines), 1)
        response = json.loads(lines[0])
        self.assertEqual(response["jsonrpc"], "2.0")
        self.assertEqual(response["id"], 1)
        self.assertEqual(response["result"]["protocolVersion"], "2025-11-25")

    def test_stdio_cancel_notification_logs_to_stderr(self):
        jsonrpc_mod.register_pending_request("req-1")
        try:
            transport_stdout, process_stdout, process_stderr = self._run_stdio([
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
            jsonrpc_mod.unregister_pending_request("req-1")

        self.assertEqual(transport_stdout, b"")
        self.assertEqual(process_stdout, "")
        self.assertIn("Cancelled request req-1", process_stderr)


if __name__ == "__main__":
    unittest.main()
