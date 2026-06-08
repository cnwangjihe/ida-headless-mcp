import json
import os
import socket
import threading
import time
import unittest
from http.server import ThreadingHTTPServer

from websockets.sync.client import connect

from ida_pro_mcp.idalib_pool_server import build_pool_handler_class


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
        session_id,
        allow_duplicate_input,
    ):
        self.registered = {
            "input_path": input_path,
            "idb_path": idb_path,
            "session_id": session_id,
            "allow_duplicate_input": allow_duplicate_input,
        }
        return {
            "success": True,
            "session": {
                "session_id": session_id or "ext1",
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
            self.assertEqual(register_response["session"]["session_id"], "win-gui")

            ws.send(json.dumps({"type": "check_agents"}))
            agent_count = json.loads(ws.recv())
            self.assertEqual(agent_count["type"], "agent_count")
            self.assertEqual(agent_count["active_agents"], 0)

        self.assertEqual(pool.registered["input_path"], r"C:\work\a.exe")
        self.assertEqual(pool.registered["idb_path"], r"C:\work\a.i64")
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and not pool.unregistered:
            time.sleep(0.05)
        self.assertEqual(pool.unregistered, ["win-gui"])


if __name__ == "__main__":
    unittest.main()
