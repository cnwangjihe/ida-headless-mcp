import http.client
import json
import unittest

from ida_pro_mcp import idalib_pool_server

mcp_mod = idalib_pool_server._mcp_mod
jsonrpc_mod = idalib_pool_server._jsonrpc_mod
McpServer = mcp_mod.McpServer


class StreamableHttpTransportSpecTests(unittest.TestCase):
    def setUp(self):
        jsonrpc_mod._LOG_REQUESTS = False
        self.server = McpServer("ida-pro-mcp")
        self.server.require_streamable_http_session = True
        self.server.serve("127.0.0.1", 0, background=True)
        self.port = self.server._http_server.server_port

    def tearDown(self):
        self.server.stop()

    def _request(self, method, path="/mcp", body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        payload = json.dumps(body).encode("utf-8") if isinstance(body, dict) else body
        conn.request(method, path, payload, headers or {})
        resp = conn.getresponse()
        data = resp.read()
        result = resp.status, dict(resp.getheaders()), data
        conn.close()
        return result

    def _post(self, body, headers=None):
        request_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        request_headers.update(headers or {})
        return self._request("POST", body=body, headers=request_headers)

    def _initialize(self):
        status, headers, data = self._post({
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1.0"},
            },
            "id": 1,
        })
        self.assertEqual(status, 200, data)
        return headers["MCP-Session-Id"], json.loads(data)

    def test_initialize_returns_session_and_latest_protocol(self):
        session_id, payload = self._initialize()

        self.assertTrue(session_id)
        self.assertEqual(payload["result"]["protocolVersion"], "2025-11-25")

    def test_invalid_origin_is_forbidden(self):
        status, _headers, _data = self._post(
            {
                "jsonrpc": "2.0",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1.0"},
                },
                "id": 1,
            },
            headers={"Origin": "https://evil.example"},
        )

        self.assertEqual(status, 403)

    def test_notification_returns_accepted_with_empty_body(self):
        session_id, _payload = self._initialize()

        status, headers, data = self._post(
            {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": {},
            },
            headers={
                "MCP-Session-Id": session_id,
                "MCP-Protocol-Version": "2025-11-25",
            },
        )

        self.assertEqual(status, 202)
        self.assertEqual(headers.get("Content-Length"), "0")
        self.assertEqual(data, b"")

    def test_jsonrpc_response_input_returns_accepted_with_empty_body(self):
        session_id, _payload = self._initialize()

        status, headers, data = self._post(
            {
                "jsonrpc": "2.0",
                "result": {"ok": True},
                "id": 99,
            },
            headers={
                "MCP-Session-Id": session_id,
                "MCP-Protocol-Version": "2025-11-25",
            },
        )

        self.assertEqual(status, 202)
        self.assertEqual(headers.get("Content-Length"), "0")
        self.assertEqual(data, b"")

    def test_unknown_session_returns_not_found(self):
        status, _headers, _data = self._post(
            {
                "jsonrpc": "2.0",
                "method": "tools/list",
                "params": {},
                "id": 2,
            },
            headers={
                "MCP-Session-Id": "missing-session",
                "MCP-Protocol-Version": "2025-11-25",
            },
        )

        self.assertEqual(status, 404)

    def test_unsupported_protocol_version_returns_bad_request(self):
        session_id, _payload = self._initialize()

        status, _headers, _data = self._post(
            {
                "jsonrpc": "2.0",
                "method": "tools/list",
                "params": {},
                "id": 3,
            },
            headers={
                "MCP-Session-Id": session_id,
                "MCP-Protocol-Version": "bogus",
            },
        )

        self.assertEqual(status, 400)

    def test_post_requires_streamable_http_accept_header(self):
        status, _headers, _data = self._request(
            "POST",
            body={
                "jsonrpc": "2.0",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1.0"},
                },
                "id": 1,
            },
            headers={"Content-Type": "application/json"},
        )

        self.assertEqual(status, 406)

    def test_get_and_delete_mcp_are_method_not_allowed(self):
        get_status, _headers, _data = self._request(
            "GET",
            headers={"Accept": "text/event-stream"},
        )
        delete_status, _headers, _data = self._request("DELETE")

        self.assertEqual(get_status, 405)
        self.assertEqual(delete_status, 405)


if __name__ == "__main__":
    unittest.main()
