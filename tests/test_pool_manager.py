"""Tests for idalib_pool_manager — SessionRegistry, PoolManager, and pool server dispatch.

These tests exercise the pure-Python session/context/refcount logic without
requiring idapro or running idalib_server subprocesses.
"""

import json
import threading
import unittest
from unittest.mock import MagicMock, patch

from ida_pro_mcp.idalib_pool_manager import (
    InstanceInfo,
    InstanceManager,
    PoolManager,
    SessionInfo,
    SessionRegistry,
)


# ---------------------------------------------------------------------------
# SessionRegistry unit tests
# ---------------------------------------------------------------------------

class TestSessionRegistry(unittest.TestCase):

    def setUp(self):
        self.sr = SessionRegistry()

    def test_create_and_get(self):
        sess = self.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0)
        self.assertEqual(sess.session_id, "s1")
        self.assertEqual(sess.input_path, "/tmp/a.elf")
        self.assertEqual(sess.instance_index, 0)
        self.assertIs(self.sr.get("s1"), sess)

    def test_create_duplicate_session_id_raises_without_overwrite(self):
        self.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0)

        with self.assertRaises(ValueError):
            self.sr.create("s1", "/tmp/b.elf", "/tmp/b.elf.i64", instance_index=1)

        self.assertEqual(self.sr.get("s1").input_path, "/tmp/a.elf")
        self.assertEqual(self.sr.find_by_input_path("/tmp/b.elf"), [])

    def test_create_initializes_refcount_to_zero(self):
        self.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0)
        self.assertEqual(self.sr.get_refcount("s1"), 0)

    def test_find_by_input_path(self):
        self.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0)
        self.assertEqual(self.sr.find_by_input_path("/tmp/a.elf"), ["s1"])
        self.assertEqual(self.sr.find_by_input_path("/tmp/b.elf"), [])

    def test_find_by_idb_path(self):
        self.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0)
        self.assertEqual(self.sr.find_by_idb_path("/tmp/a.elf.i64"), "s1")
        self.assertIsNone(self.sr.find_by_idb_path("/tmp/b.elf.i64"))

    def test_remove_cleans_up_everything(self):
        self.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0)
        self.sr.increment_refcount("s1")
        self.sr.bind_context("ctx-a", "s1")

        removed = self.sr.remove("s1")
        self.assertIsNotNone(removed)
        self.assertIsNone(self.sr.get("s1"))
        self.assertEqual(self.sr.find_by_input_path("/tmp/a.elf"), [])
        self.assertEqual(self.sr.get_refcount("s1"), 0)
        self.assertIsNone(self.sr.get_context_session_id("ctx-a"))

    def test_remove_nonexistent_returns_none(self):
        self.assertIsNone(self.sr.remove("nope"))

    # --- Context bindings ---

    def test_bind_and_get_context(self):
        self.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0)
        self.sr.bind_context("ctx-a", "s1")
        self.assertEqual(self.sr.get_context_session_id("ctx-a"), "s1")

    def test_bind_context_unknown_session_raises(self):
        with self.assertRaises(ValueError):
            self.sr.bind_context("ctx-a", "nonexistent")

    def test_bind_context_overwrites(self):
        self.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0)
        self.sr.create("s2", "/tmp/b.elf", "/tmp/b.elf.i64", instance_index=1)
        self.sr.bind_context("ctx-a", "s1")
        self.sr.bind_context("ctx-a", "s2")
        self.assertEqual(self.sr.get_context_session_id("ctx-a"), "s2")

    def test_unbind_context(self):
        self.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0)
        self.sr.bind_context("ctx-a", "s1")
        old = self.sr.unbind_context("ctx-a")
        self.assertEqual(old, "s1")
        self.assertIsNone(self.sr.get_context_session_id("ctx-a"))

    def test_unbind_context_nonexistent_returns_none(self):
        self.assertIsNone(self.sr.unbind_context("nope"))

    def test_unbind_session_everywhere(self):
        self.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0)
        self.sr.bind_context("ctx-a", "s1")
        self.sr.bind_context("ctx-b", "s1")
        self.sr.bind_context("ctx-c", "s1")
        self.sr._unbind_session_everywhere("s1")
        self.assertIsNone(self.sr.get_context_session_id("ctx-a"))
        self.assertIsNone(self.sr.get_context_session_id("ctx-b"))
        self.assertIsNone(self.sr.get_context_session_id("ctx-c"))

    # --- Refcounts ---

    def test_increment_decrement_refcount(self):
        self.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0)
        self.assertEqual(self.sr.increment_refcount("s1"), 1)
        self.assertEqual(self.sr.increment_refcount("s1"), 2)
        self.assertEqual(self.sr.increment_refcount("s1"), 3)
        self.assertEqual(self.sr.decrement_refcount("s1"), 2)
        self.assertEqual(self.sr.decrement_refcount("s1"), 1)
        self.assertEqual(self.sr.decrement_refcount("s1"), 0)

    def test_decrement_below_zero_clamps(self):
        self.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0)
        self.assertEqual(self.sr.decrement_refcount("s1"), 0)
        self.assertEqual(self.sr.decrement_refcount("s1"), 0)

    def test_refcount_unknown_session(self):
        self.assertEqual(self.sr.get_refcount("nope"), 0)

    # --- Listing ---

    def test_list_all_includes_refcount_and_context(self):
        self.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0)
        self.sr.create("s2", "/tmp/b.elf", "/tmp/b.elf.i64", instance_index=1)
        self.sr.increment_refcount("s1")
        self.sr.increment_refcount("s1")
        self.sr.increment_refcount("s2")
        self.sr.bind_context("ctx-a", "s1")

        result = self.sr.list_all(context_id="ctx-a")
        self.assertEqual(result["count"], 2)
        self.assertEqual(result["current_context_session_id"], "s1")

        sessions_by_id = {s["session_id"]: s for s in result["sessions"]}
        self.assertEqual(sessions_by_id["s1"]["refcount"], 2)
        self.assertTrue(sessions_by_id["s1"]["is_current_context"])
        self.assertEqual(sessions_by_id["s2"]["refcount"], 1)
        self.assertFalse(sessions_by_id["s2"]["is_current_context"])

    def test_list_all_no_context(self):
        self.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0)
        result = self.sr.list_all(context_id=None)
        self.assertIsNone(result["current_context_session_id"])
        self.assertFalse(result["sessions"][0]["is_current_context"])


# ---------------------------------------------------------------------------
# SessionRegistry — additional edge cases
# ---------------------------------------------------------------------------

class TestSessionRegistryEdgeCases(unittest.TestCase):

    def setUp(self):
        self.sr = SessionRegistry()

    def test_touch_updates_last_accessed(self):
        self.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0)
        old_ts = self.sr.get("s1").last_accessed
        import time; time.sleep(0.01)
        self.sr.touch("s1")
        self.assertGreater(self.sr.get("s1").last_accessed, old_ts)

    def test_touch_nonexistent_is_noop(self):
        self.sr.touch("nope")

    def test_generate_id_is_unique(self):
        ids = {self.sr.generate_id() for _ in range(100)}
        self.assertEqual(len(ids), 100)

    def test_generate_id_for_path_uses_name_and_hash(self):
        sid = self.sr.generate_id_for_path("/tmp/dp.i64", "/tmp/dp.i64")
        self.assertRegex(sid, r"^dp_[0-9a-f]{6}$")

    def test_generate_id_for_path_preserves_binary_suffixes(self):
        sid = self.sr.generate_id_for_path(
            "/tmp/libsg_ssl.so.1.1.i64",
            "/tmp/libsg_ssl.so.1.1.i64",
        )
        self.assertRegex(sid, r"^libsg_ssl\.so\.1\.1_[0-9a-f]{6}$")

    def test_generate_id_for_path_adds_random_suffix_on_collision(self):
        first = self.sr.generate_id_for_path("/tmp/dp.i64", "/tmp/dp.i64")
        self.sr.create(first, "/tmp/dp", "/tmp/dp.i64", instance_index=0)

        second = self.sr.generate_id_for_path("/tmp/dp.i64", "/tmp/dp.i64")

        self.assertRegex(second, r"^dp_[0-9a-f]{6}_[0-9a-f]{6}$")
        self.assertNotEqual(first, second)

    def test_unbind_session_everywhere_nonexistent_is_noop(self):
        self.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0)
        self.sr.bind_context("ctx-a", "s1")
        self.sr._unbind_session_everywhere("nonexistent")
        self.assertEqual(self.sr.get_context_session_id("ctx-a"), "s1")

    def test_unbind_session_everywhere_preserves_other_bindings(self):
        self.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0)
        self.sr.create("s2", "/tmp/b.elf", "/tmp/b.elf.i64", instance_index=1)
        self.sr.bind_context("ctx-a", "s1")
        self.sr.bind_context("ctx-b", "s2")
        self.sr.bind_context("ctx-c", "s1")
        self.sr._unbind_session_everywhere("s1")
        self.assertIsNone(self.sr.get_context_session_id("ctx-a"))
        self.assertIsNone(self.sr.get_context_session_id("ctx-c"))
        self.assertEqual(self.sr.get_context_session_id("ctx-b"), "s2")

    def test_list_all_multiple_contexts_different_sessions(self):
        self.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0)
        self.sr.create("s2", "/tmp/b.elf", "/tmp/b.elf.i64", instance_index=1)
        self.sr.bind_context("ctx-a", "s1")
        self.sr.bind_context("ctx-b", "s2")
        result_a = self.sr.list_all(context_id="ctx-a")
        result_b = self.sr.list_all(context_id="ctx-b")
        self.assertEqual(result_a["current_context_session_id"], "s1")
        self.assertEqual(result_b["current_context_session_id"], "s2")
        by_id_a = {s["session_id"]: s for s in result_a["sessions"]}
        self.assertTrue(by_id_a["s1"]["is_current_context"])
        self.assertFalse(by_id_a["s2"]["is_current_context"])

    def test_list_all_unbound_context(self):
        """Context that is not bound to any session."""
        self.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0)
        result = self.sr.list_all(context_id="ctx-unbound")
        self.assertIsNone(result["current_context_session_id"])
        self.assertFalse(result["sessions"][0]["is_current_context"])

    def test_remove_with_multiple_contexts_and_refcount(self):
        """remove() should clean up all contexts and refcount."""
        self.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0)
        self.sr.increment_refcount("s1")
        self.sr.increment_refcount("s1")
        self.sr.bind_context("ctx-a", "s1")
        self.sr.bind_context("ctx-b", "s1")
        self.sr.remove("s1")
        self.assertIsNone(self.sr.get_context_session_id("ctx-a"))
        self.assertIsNone(self.sr.get_context_session_id("ctx-b"))
        self.assertEqual(self.sr.get_refcount("s1"), 0)
        self.assertEqual(len(self.sr.sessions), 0)


# ---------------------------------------------------------------------------
# Dual path indexing tests
# ---------------------------------------------------------------------------

class TestDualPathIndex(unittest.TestCase):

    def setUp(self):
        self.sr = SessionRegistry()

    def test_input_path_one_to_many(self):
        """Multiple sessions can share the same input_path."""
        self.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0)
        self.sr.create("s2", "/tmp/a.elf", "/other/copy.i64", instance_index=1)
        self.assertEqual(sorted(self.sr.find_by_input_path("/tmp/a.elf")), ["s1", "s2"])

    def test_idb_path_one_to_one(self):
        """Each IDB path maps to exactly one session."""
        self.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0)
        self.sr.create("s2", "/tmp/a.elf", "/other/copy.i64", instance_index=1)
        self.assertEqual(self.sr.find_by_idb_path("/tmp/a.elf.i64"), "s1")
        self.assertEqual(self.sr.find_by_idb_path("/other/copy.i64"), "s2")

    def test_remove_cleans_both_indices(self):
        self.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0)
        self.sr.create("s2", "/tmp/a.elf", "/other/copy.i64", instance_index=1)
        self.sr.remove("s1")
        self.assertEqual(self.sr.find_by_input_path("/tmp/a.elf"), ["s2"])
        self.assertIsNone(self.sr.find_by_idb_path("/tmp/a.elf.i64"))
        self.assertEqual(self.sr.find_by_idb_path("/other/copy.i64"), "s2")

    def test_remove_last_cleans_input_path_index(self):
        self.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0)
        self.sr.remove("s1")
        self.assertEqual(self.sr.find_by_input_path("/tmp/a.elf"), [])

    def test_disambiguate_prefers_same_directory(self):
        """IDB in the same directory as input_path wins."""
        import time
        self.sr.create("s1", "/tmp/a.elf", "/other/old.i64", instance_index=0)
        time.sleep(0.01)
        self.sr.create("s2", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=1)
        result = self.sr.disambiguate(["s1", "s2"], "/tmp/a.elf")
        self.assertEqual(result, "s2")

    def test_disambiguate_falls_back_to_earliest(self):
        """When no IDB is in the same directory, pick earliest."""
        import time
        self.sr.create("s1", "/tmp/a.elf", "/dir1/x.i64", instance_index=0)
        time.sleep(0.01)
        self.sr.create("s2", "/tmp/a.elf", "/dir2/y.i64", instance_index=1)
        result = self.sr.disambiguate(["s1", "s2"], "/tmp/a.elf")
        self.assertEqual(result, "s1")

    def test_empty_idb_path(self):
        """Sessions with empty idb_path should not pollute idb index."""
        self.sr.create("s1", "/tmp/a.elf", "", instance_index=0)
        self.assertIsNone(self.sr.find_by_idb_path(""))
        self.assertEqual(self.sr.find_by_input_path("/tmp/a.elf"), ["s1"])

    def test_to_dict_includes_idb_path_and_is_external(self):
        sess = self.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0, is_external=True)
        d = sess.to_dict(refcount=1)
        self.assertEqual(d["idb_path"], "/tmp/a.elf.i64")
        self.assertTrue(d["is_external"])


# ---------------------------------------------------------------------------
# SessionInfo tests
# ---------------------------------------------------------------------------

class TestSessionInfo(unittest.TestCase):

    def test_to_dict_includes_refcount(self):
        sess = SessionInfo(session_id="s1", input_path="/tmp/a.elf", idb_path="/tmp/a.elf.i64", instance_index=0)
        d = sess.to_dict(refcount=3)
        self.assertEqual(d["session_id"], "s1")
        self.assertEqual(d["input_path"], "/tmp/a.elf")
        self.assertEqual(d["filename"], "a.elf")
        self.assertEqual(d["refcount"], 3)
        self.assertEqual(d["instance_index"], 0)

    def test_to_dict_default_refcount_zero(self):
        sess = SessionInfo(session_id="s1", input_path="/tmp/a.elf", idb_path="/tmp/a.elf.i64", instance_index=0)
        d = sess.to_dict()
        self.assertEqual(d["refcount"], 0)


# ---------------------------------------------------------------------------
# Pool server dispatch tests (with mocked PoolManager)
# ---------------------------------------------------------------------------

class TestPoolServerDispatch(unittest.TestCase):
    """Test the build_dispatch routing logic with a mocked pool."""

    def setUp(self):
        from ida_pro_mcp import idalib_pool_server

        self.mcp_mod = idalib_pool_server._mcp_mod
        self.McpServer = self.mcp_mod.McpServer
        self.build_dispatch = idalib_pool_server.build_dispatch
        self.pool_server = idalib_pool_server

    def _make_mcp_and_pool(self):
        mcp = self.McpServer("test")
        pool = MagicMock(spec=PoolManager)
        pool._lock = threading.Lock()
        pool.sr = SessionRegistry()
        pool.forward_tools_list.return_value = [
            {"name": "get_functions", "inputSchema": {"type": "object", "properties": {}}},
        ]
        pool.get_context_session_id.side_effect = lambda ctx: pool.sr.get_context_session_id(ctx)
        pool.bind_context.side_effect = lambda ctx, sid: pool.sr.bind_context(ctx, sid)
        pool.unbind_context.side_effect = lambda ctx: pool.sr.unbind_context(ctx)
        pool.increment_refcount.side_effect = lambda sid: pool.sr.increment_refcount(sid)
        pool.decrement_refcount.side_effect = lambda sid: pool.sr.decrement_refcount(sid)
        pool.get_refcount.side_effect = lambda sid: pool.sr.get_refcount(sid)
        pool.list_sessions.side_effect = lambda context_id=None: pool.sr.list_all(context_id=context_id)
        return mcp, pool

    def _dispatch(self, mcp, request, transport_session_id=None):
        """Dispatch a request with optional transport session context."""
        setattr(mcp._transport_session_id, "data", transport_session_id)
        try:
            return mcp.registry.dispatch(request)
        finally:
            setattr(mcp._transport_session_id, "data", None)

    def test_open_binds_context_and_increments_refcount(self):
        mcp, pool = self._make_mcp_and_pool()
        pool.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0)
        pool.open_session.return_value = {
            "success": True,
            "existing": False,
            "session": pool.sr.get("s1").to_dict(),
            "message": "created",
        }
        self.build_dispatch(mcp, pool)

        request = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "idalib_open", "arguments": {"input_path": "/tmp/a.elf"}},
            "id": 1,
        }
        resp = self._dispatch(mcp, request, transport_session_id="sse:agent-a")

        self.assertNotIn("error", resp)
        result = resp["result"]["structuredContent"]
        self.assertTrue(result["success"])
        self.assertEqual(result["session"]["refcount"], 1)
        self.assertEqual(pool.sr.get_context_session_id("sse:agent-a"), "s1")
        self.assertEqual(pool.sr.get_refcount("s1"), 1)

    def test_open_ignores_legacy_session_id_argument(self):
        mcp, pool = self._make_mcp_and_pool()
        pool.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0)
        pool.open_session.return_value = {
            "success": True,
            "existing": False,
            "session": pool.sr.get("s1").to_dict(),
            "message": "created",
        }
        self.build_dispatch(mcp, pool)

        request = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "idalib_open",
                "arguments": {"input_path": "/tmp/a.elf", "session_id": "dp"},
            },
            "id": 1,
        }
        self._dispatch(mcp, request, transport_session_id="sse:agent-a")

        pool.open_session.assert_called_once_with(
            "/tmp/a.elf",
            run_auto_analysis=True,
            allow_duplicate_input=False,
        )

    def test_open_existing_binary_shares_session(self):
        mcp, pool = self._make_mcp_and_pool()
        pool.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0)
        pool.open_session.return_value = {
            "success": True,
            "existing": True,
            "session": pool.sr.get("s1").to_dict(),
            "message": "existing",
        }
        self.build_dispatch(mcp, pool)

        # Agent A opens
        req = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "idalib_open", "arguments": {"input_path": "/tmp/a.elf"}},
            "id": 1,
        }
        self._dispatch(mcp, req, transport_session_id="sse:agent-a")
        # Agent B opens same binary
        self._dispatch(mcp, req, transport_session_id="sse:agent-b")

        self.assertEqual(pool.sr.get_refcount("s1"), 2)
        self.assertEqual(pool.sr.get_context_session_id("sse:agent-a"), "s1")
        self.assertEqual(pool.sr.get_context_session_id("sse:agent-b"), "s1")

    def test_close_decrements_refcount_session_stays(self):
        mcp, pool = self._make_mcp_and_pool()
        pool.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0)
        pool.sr.increment_refcount("s1")
        pool.sr.increment_refcount("s1")
        pool.sr.bind_context("sse:agent-a", "s1")
        pool.sr.bind_context("sse:agent-b", "s1")
        self.build_dispatch(mcp, pool)

        req = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "idalib_close", "arguments": {}},
            "id": 1,
        }
        resp = self._dispatch(mcp, req, transport_session_id="sse:agent-a")

        result = resp["result"]["structuredContent"]
        self.assertTrue(result["success"])
        self.assertFalse(result["closed"])
        self.assertEqual(result["refcount"], 1)
        self.assertIsNone(pool.sr.get_context_session_id("sse:agent-a"))
        self.assertEqual(pool.sr.get_context_session_id("sse:agent-b"), "s1")
        pool.close_session.assert_not_called()

    def test_close_refcount_zero_closes_session(self):
        mcp, pool = self._make_mcp_and_pool()
        pool.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0)
        pool.sr.increment_refcount("s1")
        pool.sr.bind_context("sse:agent-a", "s1")
        pool.close_session.return_value = {"success": True, "message": "closed"}
        self.build_dispatch(mcp, pool)

        req = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "idalib_close", "arguments": {}},
            "id": 1,
        }
        resp = self._dispatch(mcp, req, transport_session_id="sse:agent-a")

        result = resp["result"]["structuredContent"]
        self.assertTrue(result["success"])
        self.assertTrue(result["closed"])
        pool.close_session.assert_called_once_with("s1")

    def test_close_force_ignores_refcount(self):
        mcp, pool = self._make_mcp_and_pool()
        pool.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0)
        pool.sr.increment_refcount("s1")
        pool.sr.increment_refcount("s1")
        pool.sr.increment_refcount("s1")
        pool.sr.bind_context("sse:agent-a", "s1")
        pool.sr.bind_context("sse:agent-b", "s1")
        pool.sr.bind_context("sse:agent-c", "s1")
        pool.close_session.return_value = {"success": True, "message": "force closed"}
        self.build_dispatch(mcp, pool)

        req = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "idalib_close", "arguments": {"force": True}},
            "id": 1,
        }
        resp = self._dispatch(mcp, req, transport_session_id="sse:agent-a")

        result = resp["result"]["structuredContent"]
        self.assertTrue(result["closed"])
        pool.close_session.assert_called_once_with("s1")
        # All bindings cleared
        self.assertIsNone(pool.sr.get_context_session_id("sse:agent-a"))
        self.assertIsNone(pool.sr.get_context_session_id("sse:agent-b"))
        self.assertIsNone(pool.sr.get_context_session_id("sse:agent-c"))

    def test_close_no_session_bound_returns_error(self):
        mcp, pool = self._make_mcp_and_pool()
        self.build_dispatch(mcp, pool)

        req = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "idalib_close", "arguments": {}},
            "id": 1,
        }
        resp = self._dispatch(mcp, req, transport_session_id="sse:agent-a")

        result = resp["result"]["structuredContent"]
        self.assertIn("error", result)

    def test_switch_changes_routing_without_refcount(self):
        mcp, pool = self._make_mcp_and_pool()
        pool.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0)
        pool.sr.create("s2", "/tmp/b.elf", "/tmp/b.elf.i64", instance_index=1)
        pool.sr.increment_refcount("s1")
        pool.sr.bind_context("sse:agent-a", "s1")
        self.build_dispatch(mcp, pool)

        req = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "idalib_switch", "arguments": {"session_id": "s2"}},
            "id": 1,
        }
        resp = self._dispatch(mcp, req, transport_session_id="sse:agent-a")

        result = resp["result"]["structuredContent"]
        self.assertTrue(result["success"])
        self.assertEqual(pool.sr.get_context_session_id("sse:agent-a"), "s2")
        # Refcounts unchanged
        self.assertEqual(pool.sr.get_refcount("s1"), 1)
        self.assertEqual(pool.sr.get_refcount("s2"), 0)

    def test_switch_nonexistent_session_returns_error(self):
        mcp, pool = self._make_mcp_and_pool()
        self.build_dispatch(mcp, pool)

        req = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "idalib_switch", "arguments": {"session_id": "nope"}},
            "id": 1,
        }
        resp = self._dispatch(mcp, req, transport_session_id="sse:agent-a")

        result = resp["result"]["structuredContent"]
        self.assertFalse(result["success"])
        self.assertIn("error", result)

    def test_tool_routing_uses_context_binding(self):
        mcp, pool = self._make_mcp_and_pool()
        pool.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0)
        pool.sr.bind_context("sse:agent-a", "s1")
        mock_inst = MagicMock(spec=InstanceInfo)
        mock_sess = pool.sr.get("s1")
        pool.resolve_session_instance.return_value = (mock_sess, mock_inst)
        pool.forward_raw.return_value = {
            "jsonrpc": "2.0",
            "result": {"content": [{"type": "text", "text": "ok"}]},
            "id": 1,
        }
        self.build_dispatch(mcp, pool)

        req = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "get_functions", "arguments": {}},
            "id": 1,
        }
        resp = self._dispatch(mcp, req, transport_session_id="sse:agent-a")

        self.assertNotIn("error", resp)
        pool.resolve_session_instance.assert_called_once_with("s1")

    def test_tool_routing_explicit_session_id_overrides_context(self):
        mcp, pool = self._make_mcp_and_pool()
        pool.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0)
        pool.sr.create("s2", "/tmp/b.elf", "/tmp/b.elf.i64", instance_index=1)
        pool.sr.bind_context("sse:agent-a", "s1")
        mock_inst = MagicMock(spec=InstanceInfo)
        pool.resolve_session_instance.return_value = (pool.sr.get("s2"), mock_inst)
        pool.forward_raw.return_value = {
            "jsonrpc": "2.0",
            "result": {"content": [{"type": "text", "text": "ok"}]},
            "id": 1,
        }
        self.build_dispatch(mcp, pool)

        req = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "get_functions", "arguments": {"session_id": "s2"}},
            "id": 1,
        }
        resp = self._dispatch(mcp, req, transport_session_id="sse:agent-a")

        self.assertNotIn("error", resp)
        pool.resolve_session_instance.assert_called_once_with("s2")

    def test_tool_routing_no_session_returns_error(self):
        mcp, pool = self._make_mcp_and_pool()
        self.build_dispatch(mcp, pool)

        req = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "get_functions", "arguments": {}},
            "id": 1,
        }
        resp = self._dispatch(mcp, req, transport_session_id="sse:agent-a")

        self.assertIn("error", resp)
        self.assertIn("No session bound", resp["error"]["message"])

    def test_list_returns_context_info(self):
        mcp, pool = self._make_mcp_and_pool()
        pool.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0)
        pool.sr.increment_refcount("s1")
        pool.sr.bind_context("sse:agent-a", "s1")
        self.build_dispatch(mcp, pool)

        req = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "idalib_list", "arguments": {}},
            "id": 1,
        }
        resp = self._dispatch(mcp, req, transport_session_id="sse:agent-a")

        result = resp["result"]["structuredContent"]
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["current_context_session_id"], "s1")
        self.assertTrue(result["sessions"][0]["is_current_context"])
        self.assertEqual(result["sessions"][0]["refcount"], 1)

    def test_current_returns_bound_session(self):
        mcp, pool = self._make_mcp_and_pool()
        pool.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0)
        pool.sr.increment_refcount("s1")
        pool.sr.bind_context("sse:agent-a", "s1")
        self.build_dispatch(mcp, pool)

        req = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "idalib_current", "arguments": {}},
            "id": 1,
        }
        resp = self._dispatch(mcp, req, transport_session_id="sse:agent-a")

        result = resp["result"]["structuredContent"]
        self.assertEqual(result["session_id"], "s1")

    def test_current_no_binding_returns_error(self):
        mcp, pool = self._make_mcp_and_pool()
        self.build_dispatch(mcp, pool)

        req = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "idalib_current", "arguments": {}},
            "id": 1,
        }
        resp = self._dispatch(mcp, req, transport_session_id="sse:agent-a")

        result = resp["result"]["structuredContent"]
        self.assertIn("error", result)

    def test_resource_routing_uses_context(self):
        mcp, pool = self._make_mcp_and_pool()
        pool.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0)
        pool.sr.bind_context("sse:agent-a", "s1")
        mock_inst = MagicMock(spec=InstanceInfo)
        pool.resolve_session_instance.return_value = (pool.sr.get("s1"), mock_inst)
        pool.forward_raw.return_value = {
            "jsonrpc": "2.0",
            "result": {"contents": []},
            "id": 1,
        }
        self.build_dispatch(mcp, pool)

        req = {
            "jsonrpc": "2.0",
            "method": "resources/read",
            "params": {"uri": "ida://info"},
            "id": 1,
        }
        resp = self._dispatch(mcp, req, transport_session_id="sse:agent-a")

        self.assertNotIn("error", resp)
        pool.resolve_session_instance.assert_called_once_with("s1")

    def test_resource_routing_no_session_returns_error(self):
        mcp, pool = self._make_mcp_and_pool()
        self.build_dispatch(mcp, pool)

        req = {
            "jsonrpc": "2.0",
            "method": "resources/read",
            "params": {"uri": "ida://info"},
            "id": 1,
        }
        resp = self._dispatch(mcp, req, transport_session_id="sse:agent-a")

        self.assertIn("error", resp)

    # --- open edge cases ---

    def test_open_failure_returns_error(self):
        mcp, pool = self._make_mcp_and_pool()
        pool.open_session.return_value = {"error": "Failed to open binary"}
        self.build_dispatch(mcp, pool)

        req = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "idalib_open", "arguments": {"input_path": "/tmp/bad"}},
            "id": 1,
        }
        resp = self._dispatch(mcp, req, transport_session_id="sse:agent-a")

        result = resp["result"]["structuredContent"]
        self.assertIn("error", result)
        self.assertIsNone(pool.sr.get_context_session_id("sse:agent-a"))

    def test_open_without_transport_context(self):
        """stdio mode: no transport ctx → refcount still 0, no binding."""
        mcp, pool = self._make_mcp_and_pool()
        pool.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0)
        pool.open_session.return_value = {
            "success": True, "existing": False,
            "session": pool.sr.get("s1").to_dict(), "message": "created",
        }
        self.build_dispatch(mcp, pool)

        req = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "idalib_open", "arguments": {"input_path": "/tmp/a.elf"}},
            "id": 1,
        }
        resp = self._dispatch(mcp, req, transport_session_id=None)

        result = resp["result"]["structuredContent"]
        self.assertTrue(result["success"])
        self.assertEqual(pool.sr.get_refcount("s1"), 0)

    # --- close edge cases ---

    def test_close_explicit_sid_different_from_context(self):
        """Close a session that is NOT the one bound to the caller's context."""
        mcp, pool = self._make_mcp_and_pool()
        pool.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0)
        pool.sr.create("s2", "/tmp/b.elf", "/tmp/b.elf.i64", instance_index=1)
        pool.sr.increment_refcount("s1")
        pool.sr.increment_refcount("s2")
        pool.sr.bind_context("sse:agent-a", "s1")
        pool.close_session.return_value = {"success": True, "message": "closed"}
        self.build_dispatch(mcp, pool)

        req = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "idalib_close", "arguments": {"session_id": "s2"}},
            "id": 1,
        }
        resp = self._dispatch(mcp, req, transport_session_id="sse:agent-a")

        result = resp["result"]["structuredContent"]
        self.assertTrue(result["success"])
        self.assertTrue(result["closed"])
        pool.close_session.assert_called_once_with("s2")
        # Context binding to s1 should be untouched
        self.assertEqual(pool.sr.get_context_session_id("sse:agent-a"), "s1")

    def test_close_without_transport_context(self):
        """Close with explicit session_id but no transport context."""
        mcp, pool = self._make_mcp_and_pool()
        pool.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0)
        pool.sr.increment_refcount("s1")
        pool.close_session.return_value = {"success": True, "message": "closed"}
        self.build_dispatch(mcp, pool)

        req = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "idalib_close", "arguments": {"session_id": "s1"}},
            "id": 1,
        }
        resp = self._dispatch(mcp, req, transport_session_id=None)

        result = resp["result"]["structuredContent"]
        self.assertTrue(result["success"])
        self.assertTrue(result["closed"])

    def test_close_without_context_and_without_sid_returns_error(self):
        """No transport context and no explicit session_id → error."""
        mcp, pool = self._make_mcp_and_pool()
        self.build_dispatch(mcp, pool)

        req = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "idalib_close", "arguments": {}},
            "id": 1,
        }
        resp = self._dispatch(mcp, req, transport_session_id=None)

        result = resp["result"]["structuredContent"]
        self.assertIn("error", result)

    # --- switch edge cases ---

    def test_switch_without_transport_context_returns_error(self):
        mcp, pool = self._make_mcp_and_pool()
        pool.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0)
        self.build_dispatch(mcp, pool)

        req = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "idalib_switch", "arguments": {"session_id": "s1"}},
            "id": 1,
        }
        resp = self._dispatch(mcp, req, transport_session_id=None)

        result = resp["result"]["structuredContent"]
        self.assertFalse(result["success"])
        self.assertIn("error", result)

    # --- current edge cases ---

    def test_current_without_transport_context_returns_error(self):
        mcp, pool = self._make_mcp_and_pool()
        self.build_dispatch(mcp, pool)

        req = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "idalib_current", "arguments": {}},
            "id": 1,
        }
        resp = self._dispatch(mcp, req, transport_session_id=None)

        result = resp["result"]["structuredContent"]
        self.assertIn("error", result)

    def test_current_stale_binding(self):
        """Context points to a session that was removed externally."""
        mcp, pool = self._make_mcp_and_pool()
        pool.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0)
        pool.sr.bind_context("sse:agent-a", "s1")
        self.build_dispatch(mcp, pool)

        # Remove the session out-of-band
        pool.sr.sessions.pop("s1")

        req = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "idalib_current", "arguments": {}},
            "id": 1,
        }
        resp = self._dispatch(mcp, req, transport_session_id="sse:agent-a")

        result = resp["result"]["structuredContent"]
        self.assertIn("error", result)
        self.assertIn("no longer exists", result["error"])

    # --- save/health/warmup routing ---

    def test_save_routes_to_context_session(self):
        mcp, pool = self._make_mcp_and_pool()
        pool.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0)
        pool.sr.bind_context("sse:agent-a", "s1")
        mock_inst = MagicMock(spec=InstanceInfo)
        pool.resolve_session_instance.return_value = (pool.sr.get("s1"), mock_inst)
        pool.forward_tool_call.return_value = {"ok": True, "path": "/tmp/a.i64"}
        self.build_dispatch(mcp, pool)

        req = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "idalib_save", "arguments": {}},
            "id": 1,
        }
        resp = self._dispatch(mcp, req, transport_session_id="sse:agent-a")

        result = resp["result"]["structuredContent"]
        self.assertTrue(result.get("ok"))
        pool.resolve_session_instance.assert_called_once_with("s1")

    def test_save_maps_to_idb_save_for_external_session(self):
        mcp, pool = self._make_mcp_and_pool()
        pool.sr.create("ext1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0, is_external=True)
        pool.sr.bind_context("sse:agent-a", "ext1")
        bridge = MagicMock()
        bridge.alive = True
        inst = InstanceInfo(index=0, socket_path="", process=None, ws_bridge=bridge)
        pool.resolve_session_instance.return_value = (pool.sr.get("ext1"), inst)
        pool.forward_tool_call.return_value = {"ok": True, "path": "/tmp/a.elf.i64"}
        self.build_dispatch(mcp, pool)

        req = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "idalib_save", "arguments": {"path": "/tmp/a.elf.i64"}},
            "id": 1,
        }
        resp = self._dispatch(mcp, req, transport_session_id="sse:agent-a")

        result = resp["result"]["structuredContent"]
        self.assertTrue(result.get("ok"))
        pool.forward_tool_call.assert_called_once_with(
            inst, "idb_save", {"path": "/tmp/a.elf.i64"}
        )

    def test_save_no_session_returns_error(self):
        mcp, pool = self._make_mcp_and_pool()
        self.build_dispatch(mcp, pool)

        req = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "idalib_save", "arguments": {}},
            "id": 1,
        }
        resp = self._dispatch(mcp, req, transport_session_id="sse:agent-a")

        result = resp["result"]["structuredContent"]
        self.assertIn("error", result)

    def test_health_routes_to_context_session(self):
        mcp, pool = self._make_mcp_and_pool()
        pool.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0)
        pool.sr.bind_context("sse:agent-a", "s1")
        mock_inst = MagicMock(spec=InstanceInfo)
        pool.resolve_session_instance.return_value = (pool.sr.get("s1"), mock_inst)
        pool.forward_tool_call.return_value = {"ready": True, "status": "ok"}
        self.build_dispatch(mcp, pool)

        req = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "idalib_health", "arguments": {}},
            "id": 1,
        }
        resp = self._dispatch(mcp, req, transport_session_id="sse:agent-a")

        result = resp["result"]["structuredContent"]
        self.assertTrue(result.get("ready"))

    def test_health_maps_to_server_health_for_external_session(self):
        mcp, pool = self._make_mcp_and_pool()
        pool.sr.create("ext1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0, is_external=True)
        pool.sr.increment_refcount("ext1")
        pool.sr.bind_context("sse:agent-a", "ext1")
        bridge = MagicMock()
        bridge.alive = True
        inst = InstanceInfo(index=0, socket_path="", process=None, ws_bridge=bridge)
        pool.resolve_session_instance.return_value = (pool.sr.get("ext1"), inst)
        pool.forward_tool_call.return_value = {"status": "ok", "module": "a.elf"}
        self.build_dispatch(mcp, pool)

        req = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "idalib_health", "arguments": {}},
            "id": 1,
        }
        resp = self._dispatch(mcp, req, transport_session_id="sse:agent-a")

        result = resp["result"]["structuredContent"]
        self.assertTrue(result.get("ready"))
        self.assertEqual(result["health"]["status"], "ok")
        self.assertTrue(result["session"]["is_external"])
        pool.forward_tool_call.assert_called_once_with(inst, "server_health", {})

    def test_health_no_session_returns_error(self):
        mcp, pool = self._make_mcp_and_pool()
        self.build_dispatch(mcp, pool)

        req = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "idalib_health", "arguments": {}},
            "id": 1,
        }
        resp = self._dispatch(mcp, req, transport_session_id="sse:agent-a")

        result = resp["result"]["structuredContent"]
        self.assertIn("error", result)

    def test_warmup_routes_to_context_session(self):
        mcp, pool = self._make_mcp_and_pool()
        pool.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0)
        pool.sr.bind_context("sse:agent-a", "s1")
        mock_inst = MagicMock(spec=InstanceInfo)
        pool.resolve_session_instance.return_value = (pool.sr.get("s1"), mock_inst)
        pool.forward_tool_call.return_value = {"ok": True}
        self.build_dispatch(mcp, pool)

        req = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "idalib_warmup", "arguments": {}},
            "id": 1,
        }
        resp = self._dispatch(mcp, req, transport_session_id="sse:agent-a")

        result = resp["result"]["structuredContent"]
        self.assertTrue(result.get("ok"))

    def test_warmup_maps_to_server_warmup_for_external_session(self):
        mcp, pool = self._make_mcp_and_pool()
        pool.sr.create("ext1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0, is_external=True)
        pool.sr.increment_refcount("ext1")
        pool.sr.bind_context("sse:agent-a", "ext1")
        bridge = MagicMock()
        bridge.alive = True
        inst = InstanceInfo(index=0, socket_path="", process=None, ws_bridge=bridge)
        pool.resolve_session_instance.return_value = (pool.sr.get("ext1"), inst)
        pool.forward_tool_call.return_value = {"ok": True}
        self.build_dispatch(mcp, pool)

        req = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "idalib_warmup",
                "arguments": {"build_caches": False},
            },
            "id": 1,
        }
        resp = self._dispatch(mcp, req, transport_session_id="sse:agent-a")

        result = resp["result"]["structuredContent"]
        self.assertTrue(result.get("ready"))
        self.assertTrue(result["session"]["is_external"])
        pool.forward_tool_call.assert_called_once_with(
            inst, "server_warmup", {"build_caches": False}
        )

    def test_warmup_no_session_returns_error(self):
        mcp, pool = self._make_mcp_and_pool()
        self.build_dispatch(mcp, pool)

        req = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "idalib_warmup", "arguments": {}},
            "id": 1,
        }
        resp = self._dispatch(mcp, req, transport_session_id="sse:agent-a")

        result = resp["result"]["structuredContent"]
        self.assertIn("error", result)

    # --- _prepare_tools schema ---

    def test_tools_list_overrides_management_schemas(self):
        """Management tools should have pool-specific descriptions."""
        mcp, pool = self._make_mcp_and_pool()
        pool.forward_tools_list.return_value = [
            {"name": "idalib_open", "description": "old backend desc",
             "inputSchema": {"type": "object", "properties": {}}},
            {"name": "idalib_close", "description": "old backend desc",
             "inputSchema": {"type": "object", "properties": {}}},
            {"name": "list_funcs", "description": "list functions",
             "inputSchema": {"type": "object", "properties": {}}},
        ]
        self.build_dispatch(mcp, pool)

        req = {"jsonrpc": "2.0", "method": "tools/list", "id": 1}
        resp = mcp.registry.dispatch(req)

        tools_by_name = {t["name"]: t for t in resp["result"]["tools"]}
        # idalib_open should have pool-specific description (not the backend one)
        self.assertIn("idalib_close", tools_by_name["idalib_open"]["description"])
        open_props = tools_by_name["idalib_open"]["inputSchema"]["properties"]
        self.assertNotIn("session_id", open_props)
        # idalib_close should expose force param
        close_props = tools_by_name["idalib_close"]["inputSchema"]["properties"]
        self.assertIn("force", close_props)
        # non-management tool should get session_id injected
        self.assertIn("session_id", tools_by_name["list_funcs"]["inputSchema"]["properties"])

    def test_tools_list_always_exposes_management_tools(self):
        """GUI plugin tool lists do not contain idalib_*; pool must still expose them."""
        mcp, pool = self._make_mcp_and_pool()
        pool.forward_tools_list.return_value = [
            {"name": "server_health", "inputSchema": {"type": "object", "properties": {}}},
            {"name": "list_funcs", "inputSchema": {"type": "object", "properties": {}}},
        ]
        self.build_dispatch(mcp, pool)

        req = {"jsonrpc": "2.0", "method": "tools/list", "id": 1}
        resp = mcp.registry.dispatch(req)

        tool_names = {t["name"] for t in resp["result"]["tools"]}
        self.assertIn("idalib_health", tool_names)
        self.assertIn("idalib_warmup", tool_names)
        self.assertIn("idalib_current", tool_names)
        self.assertIn("server_health", tool_names)

    # --- dispatch protocol pass-through ---

    def test_initialize_passes_through(self):
        mcp, pool = self._make_mcp_and_pool()
        self.build_dispatch(mcp, pool)

        req = {
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1"},
            },
            "id": 1,
        }
        resp = mcp.registry.dispatch(req)
        self.assertIn("result", resp)
        self.assertIn("serverInfo", resp["result"])

    def test_notification_passes_through(self):
        mcp, pool = self._make_mcp_and_pool()
        self.build_dispatch(mcp, pool)

        req = {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": None,
        }
        resp = mcp.registry.dispatch(req)
        self.assertIsNone(resp)

    def test_protocol_discovery_methods_do_not_require_bound_session(self):
        mcp, pool = self._make_mcp_and_pool()
        self.build_dispatch(mcp, pool)

        expected = {
            "ping": {},
            "prompts/list": {"prompts": []},
            "resources/list": {"resources": []},
            "resources/templates/list": {"resourceTemplates": []},
        }

        for idx, (method, result) in enumerate(expected.items(), start=1):
            with self.subTest(method=method):
                req = {"jsonrpc": "2.0", "method": method, "id": idx}
                resp = self._dispatch(mcp, req, transport_session_id="sse:a")

                self.assertNotIn("error", resp)
                self.assertEqual(resp["result"], result)

        pool.resolve_session_instance.assert_not_called()

    # --- management handler exception ---

    def test_management_handler_exception_returns_error(self):
        mcp, pool = self._make_mcp_and_pool()
        pool.open_session.side_effect = RuntimeError("boom")
        self.build_dispatch(mcp, pool)

        req = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "idalib_open", "arguments": {"input_path": "/tmp/a.elf"}},
            "id": 1,
        }
        resp = self._dispatch(mcp, req, transport_session_id="sse:a")
        self.assertIn("error", resp)

    def test_removed_unbind_tool_is_absent_from_list(self):
        mcp, pool = self._make_mcp_and_pool()
        pool.forward_tools_list.return_value = [
            {"name": "get_functions", "inputSchema": {"type": "object", "properties": {}}},
        ]
        self.build_dispatch(mcp, pool)

        req = {
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": 1,
        }
        resp = mcp.registry.dispatch(req)

        tool_names = [t["name"] for t in resp["result"]["tools"]]
        self.assertIn("get_functions", tool_names)
        self.assertNotIn("idalib_unbind", tool_names)


# ---------------------------------------------------------------------------
# PoolManager unit tests (with mocked InstanceManager)
# ---------------------------------------------------------------------------

class TestPoolManager(unittest.TestCase):

    def _make_pool(self):
        pool = PoolManager(max_instances=2, socket_dir="/tmp/fake-pool")
        pool.im = MagicMock(spec=InstanceManager)
        pool.im.instances = []
        return pool

    def test_close_session_not_found(self):
        pool = self._make_pool()
        result = pool.close_session("nonexistent")
        self.assertFalse(result["success"])
        self.assertIn("not found", result["error"])

    def test_close_session_instance_gone(self):
        """Instance already dead — clean up session without forwarding."""
        pool = self._make_pool()
        pool.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=99)
        pool.im.find.return_value = None
        result = pool.close_session("s1")
        self.assertTrue(result["success"])
        self.assertTrue(result["closed"])
        self.assertIsNone(pool.sr.get("s1"))

    def test_resolve_session_not_found(self):
        pool = self._make_pool()
        with self.assertRaises(KeyError) as ctx:
            pool.resolve_session_instance("nonexistent")
        self.assertIn("not found", str(ctx.exception))

    def test_resolve_session_instance_gone(self):
        pool = self._make_pool()
        pool.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=99)
        pool.im.find.return_value = None
        with self.assertRaises(RuntimeError) as ctx:
            pool.resolve_session_instance("s1")
        self.assertIn("gone", str(ctx.exception))

    def test_bind_unbind_passthrough(self):
        pool = self._make_pool()
        pool.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0)
        pool.bind_context("ctx-a", "s1")
        self.assertEqual(pool.get_context_session_id("ctx-a"), "s1")
        pool.unbind_context("ctx-a")
        self.assertIsNone(pool.get_context_session_id("ctx-a"))

    def test_refcount_passthrough(self):
        pool = self._make_pool()
        pool.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0)
        self.assertEqual(pool.increment_refcount("s1"), 1)
        self.assertEqual(pool.increment_refcount("s1"), 2)
        self.assertEqual(pool.get_refcount("s1"), 2)
        self.assertEqual(pool.decrement_refcount("s1"), 1)

    def test_list_sessions_with_context(self):
        pool = self._make_pool()
        pool.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0)
        pool.sr.bind_context("ctx-a", "s1")
        result = pool.list_sessions(context_id="ctx-a")
        self.assertEqual(result["current_context_session_id"], "s1")

    def test_shutdown_all_clears_everything(self):
        pool = self._make_pool()
        pool.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0)
        pool.sr.increment_refcount("s1")
        pool.sr.bind_context("ctx-a", "s1")
        pool.im.instances = []
        pool.shutdown_all()
        self.assertEqual(len(pool.sr.sessions), 0)
        self.assertEqual(len(pool.sr._context_bindings), 0)
        self.assertEqual(len(pool.sr._refcounts), 0)

    def test_shutdown_all_skips_external_instance_save(self):
        pool = self._make_pool()
        pool.sr.create("ext1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0, is_external=True)
        bridge = MagicMock()
        bridge.alive = True
        inst = InstanceInfo(index=0, socket_path="", process=None, session_id="ext1", ws_bridge=bridge)
        pool.im.instances = [inst]

        pool.shutdown_all()

        pool.im.forward_tool_call.assert_not_called()
        pool.im.kill_all.assert_called_once()

    def test_open_session_path_dedup(self):
        """Opening the same path twice returns the existing session."""
        pool = self._make_pool()
        mock_inst = MagicMock()
        mock_inst.index = 0
        mock_inst.session_id = None
        pool.im.find_idle.return_value = mock_inst
        pool.im.forward_tool_call.return_value = {"success": True}

        r1 = pool.open_session("/tmp/a.elf")
        self.assertTrue(r1["success"])
        self.assertFalse(r1["existing"])
        sid = r1["session"]["session_id"]
        self.assertRegex(sid, r"^a\.elf_[0-9a-f]{6}$")

        r2 = pool.open_session("/tmp/a.elf")
        self.assertTrue(r2["success"])
        self.assertTrue(r2["existing"])
        self.assertEqual(r2["session"]["session_id"], sid)

    def test_open_session_generates_new_id_for_different_path(self):
        pool = self._make_pool()
        inst1 = MagicMock()
        inst1.index = 0
        inst1.session_id = None
        inst1.is_alive.return_value = False
        inst2 = MagicMock()
        inst2.index = 1
        inst2.session_id = None
        pool.im.find_idle.side_effect = [inst1, inst2]
        pool.im.forward_tool_call.return_value = {"success": True}

        r1 = pool.open_session("/tmp/dp.i64")
        r2 = pool.open_session("/other/dp.i64")

        self.assertTrue(r1["success"])
        self.assertTrue(r2["success"])
        self.assertNotEqual(r1["session"]["session_id"], r2["session"]["session_id"])
        self.assertRegex(r1["session"]["session_id"], r"^dp_[0-9a-f]{6}$")
        self.assertRegex(r2["session"]["session_id"], r"^dp_[0-9a-f]{6}$")

    def test_open_session_retries_after_backend_connection_refused(self):
        pool = self._make_pool()
        inst1 = MagicMock()
        inst1.index = 0
        inst1.session_id = None
        inst1.is_alive.return_value = False
        inst2 = MagicMock()
        inst2.index = 1
        inst2.session_id = None
        pool.im.find_idle.side_effect = [inst1, inst2]
        pool.im.forward_tool_call.side_effect = [
            ConnectionRefusedError("refused"),
            {"success": True},
        ]

        result = pool.open_session("/tmp/a.elf")

        self.assertTrue(result["success"])
        pool.im.discard.assert_called_once_with(inst1)
        pool.im.kill.assert_not_called()
        self.assertEqual(pool.im.forward_tool_call.call_count, 2)


# ---------------------------------------------------------------------------
# Multi-agent scenario integration test
# ---------------------------------------------------------------------------

class TestMultiAgentScenario(unittest.TestCase):
    """End-to-end scenario from the verification plan, with mocked pool I/O."""

    def setUp(self):
        from ida_pro_mcp import idalib_pool_server
        self.mcp_mod = idalib_pool_server._mcp_mod
        self.build_dispatch = idalib_pool_server.build_dispatch

    def _dispatch(self, mcp, request, transport_session_id):
        setattr(mcp._transport_session_id, "data", transport_session_id)
        try:
            return mcp.registry.dispatch(request)
        finally:
            setattr(mcp._transport_session_id, "data", None)

    def _tool_call(self, mcp, name, arguments, ctx):
        req = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
            "id": 1,
        }
        resp = self._dispatch(mcp, req, ctx)
        return resp["result"]["structuredContent"]

    def test_full_multi_agent_lifecycle(self):
        """
        Scenario:
        1. Agent A opens crackme03 → S1, refcount=1
        2. Agent B opens typed_fixture → S2, refcount=1
        3. Agent A routes to S1, Agent B routes to S2
        4. Agent B opens crackme03 → shares S1, refcount=2
        5. Agent B switches to S2 (refcounts unchanged)
        6. Agent A closes → S1 refcount=1, stays alive
        7. Agent B closes S1 explicitly → refcount=0, S1 closes
        """
        mcp = self.mcp_mod.McpServer("test")
        pool = MagicMock(spec=PoolManager)
        pool._lock = threading.Lock()
        pool.sr = SessionRegistry()
        pool.forward_tools_list.return_value = [
            {"name": "get_functions", "inputSchema": {"type": "object", "properties": {}}},
        ]
        pool.get_context_session_id.side_effect = lambda ctx: pool.sr.get_context_session_id(ctx)
        pool.bind_context.side_effect = lambda ctx, sid: pool.sr.bind_context(ctx, sid)
        pool.unbind_context.side_effect = lambda ctx: pool.sr.unbind_context(ctx)
        pool.increment_refcount.side_effect = lambda sid: pool.sr.increment_refcount(sid)
        pool.decrement_refcount.side_effect = lambda sid: pool.sr.decrement_refcount(sid)
        pool.get_refcount.side_effect = lambda sid: pool.sr.get_refcount(sid)
        pool.list_sessions.side_effect = lambda context_id=None: pool.sr.list_all(context_id=context_id)
        pool.close_session.return_value = {"success": True, "message": "closed"}

        mock_inst_0 = MagicMock(spec=InstanceInfo)
        mock_inst_1 = MagicMock(spec=InstanceInfo)

        # Step 1: Agent A opens crackme03
        pool.sr.create("s1", "/tmp/crackme03.elf", "/tmp/crackme03.elf.i64", instance_index=0)
        pool.open_session.return_value = {
            "success": True, "existing": False,
            "session": pool.sr.get("s1").to_dict(), "message": "created",
        }
        self.build_dispatch(mcp, pool)

        r = self._tool_call(mcp, "idalib_open", {"input_path": "/tmp/crackme03.elf"}, "sse:A")
        self.assertTrue(r["success"])
        self.assertEqual(pool.sr.get_refcount("s1"), 1)
        self.assertEqual(pool.sr.get_context_session_id("sse:A"), "s1")

        # Step 2: Agent B opens typed_fixture
        pool.sr.create("s2", "/tmp/typed_fixture.elf", "/tmp/typed_fixture.elf.i64", instance_index=1)
        pool.open_session.return_value = {
            "success": True, "existing": False,
            "session": pool.sr.get("s2").to_dict(), "message": "created",
        }
        r = self._tool_call(mcp, "idalib_open", {"input_path": "/tmp/typed_fixture.elf"}, "sse:B")
        self.assertTrue(r["success"])
        self.assertEqual(pool.sr.get_refcount("s2"), 1)
        self.assertEqual(pool.sr.get_context_session_id("sse:B"), "s2")

        # Step 3: Verify routing isolation
        pool.resolve_session_instance.return_value = (pool.sr.get("s1"), mock_inst_0)
        pool.forward_raw.return_value = {"jsonrpc": "2.0", "result": {"content": [{"type": "text", "text": "crackme03 funcs"}]}, "id": 1}
        req = {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "get_functions", "arguments": {}}, "id": 1}
        self._dispatch(mcp, req, "sse:A")
        pool.resolve_session_instance.assert_called_with("s1")

        pool.resolve_session_instance.return_value = (pool.sr.get("s2"), mock_inst_1)
        self._dispatch(mcp, req, "sse:B")
        pool.resolve_session_instance.assert_called_with("s2")

        # Step 4: Agent B opens crackme03 (shares S1)
        pool.open_session.return_value = {
            "success": True, "existing": True,
            "session": pool.sr.get("s1").to_dict(), "message": "existing",
        }
        r = self._tool_call(mcp, "idalib_open", {"input_path": "/tmp/crackme03.elf"}, "sse:B")
        self.assertTrue(r["success"])
        self.assertEqual(pool.sr.get_refcount("s1"), 2)
        self.assertEqual(pool.sr.get_context_session_id("sse:B"), "s1")

        # Step 5: Agent B switches back to S2 (refcounts unchanged)
        r = self._tool_call(mcp, "idalib_switch", {"session_id": "s2"}, "sse:B")
        self.assertTrue(r["success"])
        self.assertEqual(pool.sr.get_context_session_id("sse:B"), "s2")
        self.assertEqual(pool.sr.get_refcount("s1"), 2)
        self.assertEqual(pool.sr.get_refcount("s2"), 1)

        # Step 6: Agent A closes (refcount 2→1, session stays)
        r = self._tool_call(mcp, "idalib_close", {}, "sse:A")
        self.assertTrue(r["success"])
        self.assertFalse(r["closed"])
        self.assertEqual(r["refcount"], 1)
        pool.close_session.assert_not_called()

        # Step 7: Agent B closes S1 explicitly (refcount 1→0, session closes)
        r = self._tool_call(mcp, "idalib_close", {"session_id": "s1"}, "sse:B")
        self.assertTrue(r["success"])
        self.assertTrue(r["closed"])
        pool.close_session.assert_called_once_with("s1")


# ---------------------------------------------------------------------------
# External instance registration tests
# ---------------------------------------------------------------------------

class TestExternalRegistration(unittest.TestCase):
    """Tests for external IDA plugin registration via WebSocket bridge."""

    def test_register_external_creates_session(self):
        pool = PoolManager.__new__(PoolManager)
        pool._lock = threading.Lock()
        pool.im = InstanceManager.__new__(InstanceManager)
        pool.im.instances = []
        pool.im._next_index = 0
        pool.sr = SessionRegistry()

        bridge = MagicMock()
        bridge.alive = True

        result = pool.register_external(
            bridge, "/tmp/a.elf", "/tmp/a.elf.i64", session_id="ext1",
        )
        self.assertTrue(result["success"])
        self.assertRegex(result["session"]["session_id"], r"^a\.elf_[0-9a-f]{6}$")
        self.assertTrue(result["session"]["is_external"])
        self.assertEqual(result["session"]["refcount"], 1)

    def test_register_external_idb_conflict_rejected(self):
        pool = PoolManager.__new__(PoolManager)
        pool._lock = threading.Lock()
        pool.im = InstanceManager.__new__(InstanceManager)
        pool.im.instances = []
        pool.im._next_index = 0
        pool.sr = SessionRegistry()
        pool.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=99)

        bridge = MagicMock()
        result = pool.register_external(
            bridge, "/tmp/a.elf", "/tmp/a.elf.i64", session_id="ext1",
        )
        self.assertFalse(result["success"])
        self.assertIn("already open", result["error"])

    def test_register_external_input_conflict_needs_confirm(self):
        pool = PoolManager.__new__(PoolManager)
        pool._lock = threading.Lock()
        pool.im = InstanceManager.__new__(InstanceManager)
        pool.im.instances = []
        pool.im._next_index = 0
        pool.sr = SessionRegistry()
        pool.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=99)

        bridge = MagicMock()
        result = pool.register_external(
            bridge, "/tmp/a.elf", "/tmp/other.i64", session_id="ext1",
        )
        self.assertFalse(result["success"])
        self.assertTrue(result.get("needs_confirm"))

    def test_register_external_input_conflict_with_allow(self):
        pool = PoolManager.__new__(PoolManager)
        pool._lock = threading.Lock()
        pool.im = InstanceManager.__new__(InstanceManager)
        pool.im.instances = []
        pool.im._next_index = 0
        pool.sr = SessionRegistry()
        pool.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=99)

        bridge = MagicMock()
        bridge.alive = True
        result = pool.register_external(
            bridge, "/tmp/a.elf", "/tmp/other.i64", session_id="ext1",
            allow_duplicate_input=True,
        )
        self.assertTrue(result["success"])
        self.assertRegex(result["session"]["session_id"], r"^a\.elf_[0-9a-f]{6}$")

    def test_unregister_external(self):
        pool = PoolManager.__new__(PoolManager)
        pool._lock = threading.Lock()
        pool.im = InstanceManager.__new__(InstanceManager)
        pool.im.instances = []
        pool.im._next_index = 0
        pool.sr = SessionRegistry()

        bridge = MagicMock()
        bridge.alive = True
        reg = pool.register_external(bridge, "/tmp/a.elf", "/tmp/a.elf.i64", session_id="ext1")
        sid = reg["session"]["session_id"]

        # Simulate agent refcount
        pool.sr.increment_refcount(sid)  # agent opens
        self.assertEqual(pool.sr.get_refcount(sid), 2)  # user + agent

        result = pool.unregister_external(sid)
        self.assertTrue(result["success"])
        self.assertEqual(result["active_agents"], 1)
        self.assertIsNone(pool.sr.get(sid))

    def test_get_external_agent_count(self):
        pool = PoolManager.__new__(PoolManager)
        pool._lock = threading.Lock()
        pool.im = InstanceManager.__new__(InstanceManager)
        pool.im.instances = []
        pool.im._next_index = 0
        pool.sr = SessionRegistry()

        bridge = MagicMock()
        bridge.alive = True
        reg = pool.register_external(bridge, "/tmp/a.elf", "/tmp/a.elf.i64", session_id="ext1")
        sid = reg["session"]["session_id"]
        self.assertEqual(pool.get_external_agent_count(sid), 0)

        pool.sr.increment_refcount(sid)
        self.assertEqual(pool.get_external_agent_count(sid), 1)


class TestExternalCloseGuard(TestPoolServerDispatch):
    """Tests for the close guard on external sessions."""

    def _tool_call(self, mcp, name, arguments, ctx):
        req = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
            "id": 1,
        }
        resp = self._dispatch(mcp, req, ctx)
        return resp["result"]["structuredContent"]

    def test_force_close_external_rejected(self):
        mcp, pool = self._make_mcp_and_pool()
        pool.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0, is_external=True)
        pool.sr.increment_refcount("s1")
        pool.sr.increment_refcount("s1")  # agent ref
        pool.sr.bind_context("sse:agent-a", "s1")

        self.build_dispatch(mcp, pool)
        r = self._tool_call(mcp, "idalib_close", {"force": True}, "sse:agent-a")
        self.assertFalse(r["success"])
        self.assertIn("externally registered", r["error"])

    def test_normal_close_external_keeps_session(self):
        mcp, pool = self._make_mcp_and_pool()
        pool.sr.create("s1", "/tmp/a.elf", "/tmp/a.elf.i64", instance_index=0, is_external=True)
        pool.sr.increment_refcount("s1")  # user ref
        pool.sr.increment_refcount("s1")  # agent ref
        pool.sr.bind_context("sse:agent-a", "s1")

        self.build_dispatch(mcp, pool)
        r = self._tool_call(mcp, "idalib_close", {}, "sse:agent-a")
        self.assertTrue(r["success"])
        self.assertFalse(r["closed"])
        self.assertEqual(r["refcount"], 1)
        self.assertIsNotNone(pool.sr.get("s1"))


class TestInstanceInfoExternal(unittest.TestCase):

    def test_is_external_with_ws_bridge(self):
        bridge = MagicMock()
        bridge.alive = True
        inst = InstanceInfo(index=0, socket_path="", process=None, ws_bridge=bridge)
        self.assertTrue(inst.is_external)
        self.assertTrue(inst.is_alive())

    def test_is_not_external_without_bridge(self):
        proc = MagicMock()
        proc.poll.return_value = None
        inst = InstanceInfo(index=0, socket_path="/tmp/0.sock", process=proc)
        self.assertFalse(inst.is_external)
        self.assertTrue(inst.is_alive())

    def test_external_dead_when_bridge_dead(self):
        bridge = MagicMock()
        bridge.alive = False
        inst = InstanceInfo(index=0, socket_path="", process=None, ws_bridge=bridge)
        self.assertFalse(inst.is_alive())


if __name__ == "__main__":
    unittest.main()
