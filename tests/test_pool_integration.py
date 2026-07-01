"""Integration tests for idalib pool — runs real idalib instances.

Requires IDADIR to be set to a valid IDA Pro installation.
Spawns actual idalib_server subprocesses and tests multi-agent routing
through the pool proxy.
"""

import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from http.client import HTTPConnection
from pathlib import Path

TESTS_DIR = Path(__file__).parent
CRACKME = os.path.abspath(TESTS_DIR / "crackme03.elf")
TYPED_FIXTURE = os.path.abspath(TESTS_DIR / "typed_fixture.elf")

IDADIR = os.environ.get("IDADIR", "")
SKIP_REASON = "IDADIR not set" if not IDADIR else ""


def _find_free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class PoolClient:
    """Minimal MCP client that talks Streamable HTTP with Mcp-Session-Id."""

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.session_id: str | None = None

    def request(self, method: str, params: dict | None = None) -> dict:
        body = json.dumps({
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
            "id": 1,
        })
        conn = HTTPConnection(self.host, self.port, timeout=120)
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self.session_id:
            headers["MCP-Session-Id"] = self.session_id
            headers["MCP-Protocol-Version"] = "2025-11-25"
        try:
            conn.request("POST", "/mcp", body, headers)
            resp = conn.getresponse()
            data = json.loads(resp.read().decode())
            new_sid = resp.getheader("Mcp-Session-Id")
            if new_sid:
                self.session_id = new_sid
            return data
        finally:
            conn.close()

    def initialize(self) -> dict:
        return self.request("initialize", {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1.0"},
        })

    def tool_call(self, name: str, arguments: dict | None = None) -> dict:
        resp = self.request("tools/call", {"name": name, "arguments": arguments or {}})
        if "error" in resp:
            return {"error": resp["error"].get("message", str(resp["error"]))}
        result = resp.get("result", {})
        sc = result.get("structuredContent")
        if sc:
            return sc
        content = result.get("content", [])
        if content and content[0].get("type") == "text":
            try:
                return json.loads(content[0]["text"])
            except (json.JSONDecodeError, KeyError):
                return {"text": content[0]["text"]}
        return result

    def tools_list(self) -> list[dict]:
        resp = self.request("tools/list")
        return resp.get("result", {}).get("tools", [])


@unittest.skipIf(SKIP_REASON, SKIP_REASON)
class TestPoolIntegration(unittest.TestCase):
    """Start a real pool server and run multi-agent scenarios."""

    pool_proc = None
    port = None

    @classmethod
    def setUpClass(cls):
        cls.port = _find_free_port()
        cls.socket_dir = tempfile.mkdtemp(prefix="idalib-pool-test-")

        cmd = [
            sys.executable, "-m", "ida_pro_mcp.idalib_pool_server",
            "--transport", f"http://127.0.0.1:{cls.port}",
            "--max-instances", "1",
            "--socket-dir", cls.socket_dir,
        ]
        env = {**os.environ, "IDADIR": IDADIR}
        cls.pool_proc = subprocess.Popen(
            cmd, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )

        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            try:
                with socket.socket() as sock:
                    sock.settimeout(1)
                    sock.connect(("127.0.0.1", cls.port))
                break
            except (ConnectionRefusedError, OSError):
                time.sleep(0.5)
                if cls.pool_proc.poll() is not None:
                    stdout = cls.pool_proc.stdout.read().decode()
                    raise RuntimeError(f"Pool server exited early:\n{stdout}")
        else:
            cls.pool_proc.kill()
            stdout = cls.pool_proc.stdout.read().decode() if cls.pool_proc.stdout else ""
            raise TimeoutError(f"Pool server did not start within 120s:\n{stdout}")

        print(f"\n[test] Pool server started on port {cls.port} (pid {cls.pool_proc.pid})")

    @classmethod
    def tearDownClass(cls):
        if cls.pool_proc and cls.pool_proc.poll() is None:
            cls.pool_proc.send_signal(signal.SIGTERM)
            try:
                cls.pool_proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                cls.pool_proc.kill()
                cls.pool_proc.wait(timeout=5)
        print("[test] Pool server stopped")

    def _make_client(self) -> PoolClient:
        client = PoolClient("127.0.0.1", self.port)
        client.initialize()
        self.assertIsNotNone(client.session_id, "Server should return Mcp-Session-Id")
        return client

    def test_01_tools_list_no_unbind(self):
        """Removed idalib_unbind tool should not appear in the tool list."""
        client = self._make_client()
        tools = client.tools_list()
        names = [t["name"] for t in tools]
        self.assertNotIn("idalib_unbind", names)
        self.assertIn("idalib_open", names)
        self.assertIn("list_funcs", names)

    def test_02_no_session_returns_error(self):
        """Calling a tool without opening a session first should error."""
        client = self._make_client()
        result = client.tool_call("list_funcs")
        self.assertIn("error", result, f"Expected error, got: {result}")

    def test_03_open_and_query(self):
        """Open a binary and run a basic query."""
        client = self._make_client()
        result = client.tool_call("idalib_open", {"input_path": CRACKME})
        self.assertTrue(result.get("success"), f"Open failed: {result}")
        self.assertEqual(result["session"]["refcount"], 1)

        funcs = client.tool_call("list_funcs")
        self.assertNotIn("error", funcs, f"list_funcs failed: {funcs}")

        close_result = client.tool_call("idalib_close")
        self.assertTrue(close_result.get("success"), f"Close failed: {close_result}")
        self.assertTrue(close_result.get("closed"))

    def test_04_two_agents_different_binaries(self):
        """Two agents open different binaries and get isolated routing."""
        agent_a = self._make_client()
        agent_b = self._make_client()

        r_a = agent_a.tool_call("idalib_open", {"input_path": CRACKME})
        self.assertTrue(r_a.get("success"), f"A open failed: {r_a}")
        sid_a = r_a["session"]["session_id"]

        r_b = agent_b.tool_call("idalib_open", {"input_path": TYPED_FIXTURE})
        self.assertTrue(r_b.get("success"), f"B open failed: {r_b}")
        sid_b = r_b["session"]["session_id"]

        self.assertNotEqual(sid_a, sid_b)
        self.assertEqual(r_a["session"]["refcount"], 1)
        self.assertEqual(r_b["session"]["refcount"], 1)

        cur_a = agent_a.tool_call("idalib_current")
        self.assertEqual(cur_a["session_id"], sid_a)
        self.assertIn("crackme03", cur_a["input_path"])

        cur_b = agent_b.tool_call("idalib_current")
        self.assertEqual(cur_b["session_id"], sid_b)
        self.assertIn("typed_fixture", cur_b["input_path"])

        agent_a.tool_call("idalib_close")
        agent_b.tool_call("idalib_close")

    def test_05_shared_session_refcount(self):
        """Two agents open the same binary — should share session."""
        agent_a = self._make_client()
        agent_b = self._make_client()

        r_a = agent_a.tool_call("idalib_open", {"input_path": CRACKME})
        self.assertTrue(r_a.get("success"))
        sid = r_a["session"]["session_id"]
        self.assertEqual(r_a["session"]["refcount"], 1)

        r_b = agent_b.tool_call("idalib_open", {"input_path": CRACKME})
        self.assertTrue(r_b.get("success"))
        self.assertEqual(r_b["session"]["session_id"], sid)
        self.assertEqual(r_b["session"]["refcount"], 2)

        close_a = agent_a.tool_call("idalib_close")
        self.assertTrue(close_a.get("success"))
        self.assertFalse(close_a.get("closed"))
        self.assertEqual(close_a.get("refcount"), 1)

        cur_b = agent_b.tool_call("idalib_current")
        self.assertEqual(cur_b["session_id"], sid)

        close_b = agent_b.tool_call("idalib_close")
        self.assertTrue(close_b.get("success"))
        self.assertTrue(close_b.get("closed"))

    def test_06_switch_does_not_change_refcount(self):
        """idalib_switch only changes routing, not refcount."""
        agent = self._make_client()

        r1 = agent.tool_call("idalib_open", {"input_path": CRACKME})
        self.assertTrue(r1.get("success"))
        sid1 = r1["session"]["session_id"]

        r2 = agent.tool_call("idalib_open", {"input_path": TYPED_FIXTURE})
        self.assertTrue(r2.get("success"))
        sid2 = r2["session"]["session_id"]

        cur = agent.tool_call("idalib_current")
        self.assertEqual(cur["session_id"], sid2)

        sw = agent.tool_call("idalib_switch", {"session_id": sid1})
        self.assertTrue(sw.get("success"))

        cur = agent.tool_call("idalib_current")
        self.assertEqual(cur["session_id"], sid1)

        ls = agent.tool_call("idalib_list")
        sessions_by_id = {s["session_id"]: s for s in ls["sessions"]}
        self.assertEqual(sessions_by_id[sid1]["refcount"], 1)
        self.assertEqual(sessions_by_id[sid2]["refcount"], 1)

        agent.tool_call("idalib_close", {"session_id": sid1})
        agent.tool_call("idalib_close", {"session_id": sid2})

    def test_07_force_close(self):
        """Force close should kill session regardless of refcount."""
        agent_a = self._make_client()
        agent_b = self._make_client()

        r_a = agent_a.tool_call("idalib_open", {"input_path": CRACKME})
        sid = r_a["session"]["session_id"]
        agent_b.tool_call("idalib_open", {"input_path": CRACKME})

        close = agent_a.tool_call("idalib_close", {"force": True})
        self.assertTrue(close.get("success"))
        self.assertTrue(close.get("closed"))

        cur_b = agent_b.tool_call("idalib_current")
        has_error = "error" in cur_b
        different_session = cur_b.get("session_id") != sid
        self.assertTrue(
            has_error or different_session,
            f"Expected error or different session after force close, got: {cur_b}",
        )

    def test_08_explicit_session_id_overrides_context(self):
        """Passing session_id in tool args should override context binding."""
        agent = self._make_client()

        r1 = agent.tool_call("idalib_open", {"input_path": CRACKME})
        sid1 = r1["session"]["session_id"]

        r2 = agent.tool_call("idalib_open", {"input_path": TYPED_FIXTURE})
        sid2 = r2["session"]["session_id"]

        cur = agent.tool_call("idalib_current")
        self.assertEqual(cur["session_id"], sid2)

        health = agent.tool_call("idalib_health", {"session_id": sid1})
        self.assertTrue(health.get("ready", False) or "error" not in health,
                       f"Health check for sid1 failed: {health}")

        agent.tool_call("idalib_close", {"session_id": sid1})
        agent.tool_call("idalib_close", {"session_id": sid2})


if __name__ == "__main__":
    unittest.main()
