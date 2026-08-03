import gzip
import http.client
import json
import time
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

    def test_get_mcp_is_method_not_allowed(self):
        get_status, _headers, _data = self._request(
            "GET",
            headers={"Accept": "text/event-stream"},
        )

        self.assertEqual(get_status, 405)

    def test_delete_requires_session_header(self):
        status, _headers, _data = self._request("DELETE")

        self.assertEqual(status, 400)

    def test_delete_terminates_http_session_exactly_once(self):
        closed = []
        self.server.transport_session_closed = (
            lambda context_id, reason: closed.append((context_id, reason))
        )
        session_id, _payload = self._initialize()

        status, _headers, data = self._request(
            "DELETE", headers={"MCP-Session-Id": session_id}
        )
        second_status, _headers, _data = self._request(
            "DELETE", headers={"MCP-Session-Id": session_id}
        )

        self.assertEqual(status, 204)
        self.assertEqual(data, b"")
        self.assertEqual(second_status, 404)
        self.assertEqual(
            closed,
            [(f"http:{session_id}", "client_terminated")],
        )

    def test_gzip_body_is_limited_after_decompression(self):
        self.server.post_body_limit = 512
        payload = json.dumps({
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "x" * 2000, "version": "1"},
            },
            "id": 1,
        }).encode("utf-8")
        compressed = gzip.compress(payload)
        self.assertLess(len(compressed), self.server.post_body_limit)

        status, _headers, _data = self._post(
            compressed, headers={"Content-Encoding": "gzip"}
        )

        self.assertEqual(status, 413)

    def test_valid_gzip_request_is_accepted(self):
        payload = json.dumps({
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1"},
            },
            "id": 1,
        }).encode("utf-8")

        status, _headers, data = self._post(
            gzip.compress(payload), headers={"Content-Encoding": "gzip"}
        )

        self.assertEqual(status, 200, data)

    def test_invalid_compressed_body_returns_bad_request(self):
        status, _headers, _data = self._post(
            b"not-gzip", headers={"Content-Encoding": "gzip"}
        )

        self.assertEqual(status, 400)

    def test_unknown_content_encoding_is_rejected(self):
        status, _headers, _data = self._post(
            b"{}", headers={"Content-Encoding": "br"}
        )

        self.assertEqual(status, 415)

    def test_chunked_body_is_rejected_when_cumulative_size_exceeds_limit(self):
        self.server.post_body_limit = 16
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request(
            "POST",
            "/mcp",
            body=iter([b"a" * 10, b"b" * 10]),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
            encode_chunked=True,
        )
        response = conn.getresponse()
        response.read()
        status = response.status
        conn.close()

        self.assertEqual(status, 413)

    def test_expired_http_session_is_pruned(self):
        session_id, _payload = self._initialize()
        closed = []
        self.server.transport_session_closed = (
            lambda context_id, reason: closed.append((context_id, reason))
        )
        self.server.http_session_ttl_seconds = 1
        with self.server._http_sessions_lock:
            self.server._http_sessions[session_id].last_accessed = (
                time.monotonic() - 2
            )

        status, _headers, _data = self._post(
            {
                "jsonrpc": "2.0",
                "method": "tools/list",
                "params": {},
                "id": 2,
            },
            headers={
                "MCP-Session-Id": session_id,
                "MCP-Protocol-Version": "2025-11-25",
            },
        )

        self.assertEqual(status, 404)
        with self.server._http_sessions_lock:
            self.assertNotIn(session_id, self.server._http_sessions)
        self.assertEqual(
            closed,
            [(f"http:{session_id}", "idle_timeout")],
        )

    def test_http_session_registry_evicts_oldest_entry_at_capacity(self):
        closed = []
        self.server.transport_session_closed = (
            lambda context_id, reason: closed.append((context_id, reason))
        )
        self.server.http_session_max_entries = 2
        self.server.register_http_session("first")
        self.server.register_http_session("second")
        self.server.register_http_session("third")

        with self.server._http_sessions_lock:
            self.assertNotIn("first", self.server._http_sessions)
            self.assertIn("second", self.server._http_sessions)
            self.assertIn("third", self.server._http_sessions)
        self.assertEqual(
            closed,
            [("http:first", "capacity_evicted")],
        )

    def test_capacity_allows_temporary_overflow_when_all_entries_active(self):
        closed = []
        self.server.transport_session_closed = (
            lambda context_id, reason: closed.append((context_id, reason))
        )
        self.server.http_session_max_entries = 2
        self.server.register_http_session("first")
        self.server.register_http_session("second")
        self.assertTrue(self.server.begin_transport_request("http:first"))
        self.assertTrue(self.server.begin_transport_request("http:second"))

        self.server.register_http_session("third")

        with self.server._http_sessions_lock:
            self.assertEqual(len(self.server._http_sessions), 3)
        self.assertEqual(closed, [])

        self.server.end_transport_request("http:first")
        self.server.touch_http_session("first")

        with self.server._http_sessions_lock:
            self.assertEqual(len(self.server._http_sessions), 2)
            self.assertIn("first", self.server._http_sessions)
            self.assertIn("second", self.server._http_sessions)
            self.assertNotIn("third", self.server._http_sessions)
        self.assertEqual(closed, [("http:third", "capacity_evicted")])
        self.server.end_transport_request("http:second")

    def test_idle_ttl_zero_disables_expiration(self):
        self.server.http_session_ttl_seconds = 0
        self.server.register_http_session("persistent")
        with self.server._http_sessions_lock:
            self.server._http_sessions["persistent"].last_accessed = 0

        self.server.reap_http_sessions()

        self.assertTrue(self.server.has_http_session("persistent"))

    def test_background_reaper_expires_idle_session_without_new_request(self):
        import threading

        self.server.stop()
        self.server = McpServer("ida-pro-mcp")
        self.server.require_streamable_http_session = True
        self.server.http_session_ttl_seconds = 0.1
        closed = []
        closed_event = threading.Event()

        def on_closed(context_id, reason):
            closed.append((context_id, reason))
            closed_event.set()

        self.server.transport_session_closed = on_closed
        self.server.register_http_session("idle")
        self.server.serve("127.0.0.1", 0, background=True)

        self.assertTrue(closed_event.wait(2))
        self.assertEqual(closed, [("http:idle", "idle_timeout")])
        self.assertFalse(self.server.has_http_session("idle"))


if __name__ == "__main__":
    unittest.main()
