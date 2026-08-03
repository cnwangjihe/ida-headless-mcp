import http.client
import json
import os
import socket
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from unittest.mock import MagicMock

from websockets.sync.client import connect

from ida_pro_mcp.idalib_pool_manager import InstanceInfo, PoolManager, SessionRegistry
from ida_pro_mcp.idalib_pool_server import (
    McpServer,
    PoolOutputCache,
    build_dispatch,
    build_pool_handler_class,
)


class _DummyMcp:
    auth_token = None


class _DummyPool:
    def __init__(self):
        self.registered = None
        self.unregistered = []

    def register_external(
        self,
        *,
        ws_bridge,
        input_path,
        idb_path,
        allow_duplicate_input,
    ):
        self.registered = {
            "input_path": input_path,
            "idb_path": idb_path,
            "allow_duplicate_input": allow_duplicate_input,
        }
        return {
            "success": True,
            "session": {
                "session_id": "a_123abc",
                "input_path": input_path,
                "idb_path": idb_path,
                "filename": os.path.basename(input_path),
                "refcount": 1,
                "is_external": True,
                "last_accessed": 0,
                "instance_index": 0,
            },
        }

    def get_external_agent_count(self, session_id):
        return 0

    def unregister_external(self, session_id):
        self.unregistered.append(session_id)
        return {"success": True, "active_agents": 0}


def _find_free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class TestPoolWebSocketServer(unittest.TestCase):
    def test_output_cache_evicts_oldest_entry(self):
        output_cache = PoolOutputCache(max_size=2)
        output_cache.put("first", {"value": 1})
        output_cache.put("second", {"value": 2})
        output_cache.put("third", {"value": 3})

        self.assertIsNone(output_cache.get("first"))
        self.assertEqual(output_cache.get("second"), {"value": 2})
        self.assertEqual(output_cache.get("third"), {"value": 3})

    def test_tool_response_download_url_round_trips_through_pool(self):
        output_id = "47cb1836-8b32-4e27-b1a3-82d8dc1ea6b6"
        complete = {"instructions": ["mov eax, 1", "ret"]}
        preview = {
            "instructions": ["mov eax, 1"],
            "_output_truncated": True,
            "_total_chars": len(json.dumps(complete)),
            "_output_id": output_id,
            "_download_url": f"http://127.0.0.1:13337/output/{output_id}.json",
            "_download_hint": "broken backend URL",
        }

        pool = MagicMock(spec=PoolManager)
        pool._lock = threading.Lock()
        pool.sr = SessionRegistry()
        session = pool.sr.create(
            "s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0
        )
        instance = MagicMock(spec=InstanceInfo)
        pool.acquire_session.return_value = (session, instance)
        pool.forward_raw.return_value = {
            "jsonrpc": "2.0",
            "result": {
                "structuredContent": preview,
                "content": [{"type": "text", "text": json.dumps(complete)}],
                "isError": False,
            },
            "id": 1,
        }

        mcp = McpServer("test")
        output_cache = PoolOutputCache()
        build_dispatch(mcp, pool, output_cache=output_cache)
        handler_cls = build_pool_handler_class(pool, output_cache)
        port = _find_free_port()
        server = ThreadingHTTPServer(("127.0.0.1", port), handler_cls)
        server.daemon_threads = True
        server.mcp_server = mcp
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)

        request = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "get_functions",
                "arguments": {"session_id": "s1"},
            },
            "id": 1,
        }
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        self.addCleanup(conn.close)
        conn.request(
            "POST",
            "/mcp",
            body=json.dumps(request),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                "MCP-Protocol-Version": "2025-11-25",
            },
        )
        response = conn.getresponse()
        response_body = json.loads(response.read())
        self.assertEqual(response.status, 200)

        download_url = response_body["result"]["structuredContent"][
            "_download_url"
        ]
        self.assertEqual(
            download_url,
            f"http://127.0.0.1:{port}/output/{output_id}.json",
        )

        conn.request("GET", f"/output/{output_id}.json")
        download_response = conn.getresponse()
        downloaded = json.loads(download_response.read())
        self.assertEqual(download_response.status, 200)
        self.assertEqual(downloaded, complete)

    def test_output_download_returns_complete_pool_cached_result(self):
        pool = _DummyPool()
        output_id = "47cb1836-8b32-4e27-b1a3-82d8dc1ea6b6"
        complete = {"instructions": ["mov eax, 1", "ret"]}
        output_cache = PoolOutputCache()
        output_cache.put(output_id, complete)
        handler_cls = build_pool_handler_class(pool, output_cache)
        port = _find_free_port()
        server = ThreadingHTTPServer(("127.0.0.1", port), handler_cls)
        server.daemon_threads = True
        server.mcp_server = _DummyMcp()
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)

        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        self.addCleanup(conn.close)
        conn.request("GET", f"/output/{output_id}.json")
        response = conn.getresponse()
        body = response.read()

        self.assertEqual(response.status, 200)
        self.assertEqual(json.loads(body), complete)
        self.assertEqual(
            response.getheader("Content-Disposition"),
            f'attachment; filename="{output_id}.json"',
        )

    def test_output_download_requires_pool_bearer_token(self):
        pool = _DummyPool()
        output_id = "47cb1836-8b32-4e27-b1a3-82d8dc1ea6b6"
        output_cache = PoolOutputCache()
        output_cache.put(output_id, {"complete": True})
        handler_cls = build_pool_handler_class(pool, output_cache)
        port = _find_free_port()
        server = ThreadingHTTPServer(("127.0.0.1", port), handler_cls)
        server.daemon_threads = True
        server.mcp_server = _DummyMcp()
        server.mcp_server.auth_token = "secret"
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)

        unauthorized = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        self.addCleanup(unauthorized.close)
        unauthorized.request("GET", f"/output/{output_id}.json")
        unauthorized_response = unauthorized.getresponse()
        unauthorized_response.read()
        self.assertEqual(unauthorized_response.status, 401)

        authorized = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        self.addCleanup(authorized.close)
        authorized.request(
            "GET",
            f"/output/{output_id}.json",
            headers={"Authorization": "Bearer secret"},
        )
        authorized_response = authorized.getresponse()
        body = authorized_response.read()
        self.assertEqual(authorized_response.status, 200)
        self.assertEqual(json.loads(body), {"complete": True})

    def test_pool_ws_accepts_external_registration(self):
        pool = _DummyPool()
        handler_cls = build_pool_handler_class(pool)
        port = _find_free_port()
        server = ThreadingHTTPServer(("127.0.0.1", port), handler_cls)
        server.daemon_threads = True
        server.mcp_server = _DummyMcp()
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)

        with connect(f"ws://127.0.0.1:{port}/pool/ws", proxy=None) as ws:
            ws.send(
                json.dumps(
                    {
                        "type": "register",
                        "input_path": r"C:\work\a.exe",
                        "idb_path": r"C:\work\a.i64",
                        "session_id": "win-gui",
                        "allow_duplicate_input": False,
                    }
                )
            )
            register_response = json.loads(ws.recv())
            self.assertTrue(register_response["success"])
            self.assertEqual(register_response["session"]["session_id"], "a_123abc")

            ws.send(json.dumps({"type": "check_agents"}))
            agent_count = json.loads(ws.recv())
            self.assertEqual(agent_count["type"], "agent_count")
            self.assertEqual(agent_count["active_agents"], 0)

        self.assertEqual(pool.registered["input_path"], r"C:\work\a.exe")
        self.assertEqual(pool.registered["idb_path"], r"C:\work\a.i64")
        self.assertNotIn("session_id", pool.registered)
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and not pool.unregistered:
            time.sleep(0.05)
        self.assertEqual(pool.unregistered, ["a_123abc"])

    def test_pool_ws_accepts_messages_larger_than_default_websocket_limit(self):
        pool = _DummyPool()
        handler_cls = build_pool_handler_class(pool)
        port = _find_free_port()
        server = ThreadingHTTPServer(("127.0.0.1", port), handler_cls)
        server.daemon_threads = True
        server.mcp_server = _DummyMcp()
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)

        with connect(f"ws://127.0.0.1:{port}/pool/ws", proxy=None) as ws:
            ws.send(
                json.dumps(
                    {
                        "type": "register",
                        "input_path": "/tmp/a.exe",
                        "idb_path": "/tmp/a.i64",
                        "allow_duplicate_input": False,
                    }
                )
            )
            register_response = json.loads(ws.recv())
            self.assertTrue(register_response["success"])

            ws.send(json.dumps({
                "type": "ignored",
                "payload": "x" * (1024 * 1024 + 1),
            }))
            ws.send(json.dumps({"type": "check_agents"}))

            agent_count = json.loads(ws.recv())
            self.assertEqual(agent_count["type"], "agent_count")
            self.assertEqual(agent_count["active_agents"], 0)


if __name__ == "__main__":
    unittest.main()
