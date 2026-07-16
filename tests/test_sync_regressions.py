import importlib.util
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch


def _load_sync_module():
    package = types.ModuleType("sync_test_pkg")
    package.__path__ = []

    rpc = types.ModuleType("sync_test_pkg.rpc")
    rpc.McpToolError = type("McpToolError", (Exception,), {})

    zeromcp = types.ModuleType("sync_test_pkg.zeromcp")
    zeromcp.__path__ = []
    jsonrpc = types.ModuleType("sync_test_pkg.zeromcp.jsonrpc")
    jsonrpc.get_current_cancel_event = lambda: None
    jsonrpc.RequestCancelledError = type(
        "RequestCancelledError", (Exception,), {}
    )

    idaapi = types.ModuleType("idaapi")
    idaapi.get_kernel_version = lambda: "9.3"
    idaapi.MFF_WRITE = 1
    idaapi.execute_sync = lambda callback, flags: callback()

    idc = types.ModuleType("idc")
    idc.batch = lambda value: 0

    module_name = "sync_test_pkg.sync"
    path = (
        Path(__file__).parents[1]
        / "src"
        / "ida_pro_mcp"
        / "ida_mcp"
        / "sync.py"
    )
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    modules = {
        "sync_test_pkg": package,
        "sync_test_pkg.rpc": rpc,
        "sync_test_pkg.zeromcp": zeromcp,
        "sync_test_pkg.zeromcp.jsonrpc": jsonrpc,
        "idaapi": idaapi,
        "idc": idc,
        module_name: module,
    }
    with patch.dict(sys.modules, modules):
        assert spec.loader is not None
        spec.loader.exec_module(module)
    return module


class SyncRegressionTests(unittest.TestCase):
    def setUp(self):
        self.sync = _load_sync_module()

    def test_nested_batch_error_does_not_consume_outer_stack_entry(self):
        sync = self.sync
        def inner():
            return "inner"

        def outer():
            with self.assertRaises(sync.IDASyncError):
                sync._run_with_batch(inner)
            return "outer"

        with patch.object(sync.idc, "batch", return_value=0):
            self.assertEqual(sync._run_with_batch(outer), "outer")
            self.assertEqual(sync._run_with_batch(lambda: "next"), "next")

    def test_batch_setup_failure_does_not_poison_next_call(self):
        sync = self.sync
        with patch.object(
            sync.idc, "batch", side_effect=[RuntimeError("batch failed"), 0, 0]
        ):
            with self.assertRaisesRegex(RuntimeError, "batch failed"):
                sync._run_with_batch(lambda: None)
            self.assertEqual(sync._run_with_batch(lambda: "ok"), "ok")

    def test_execute_sync_failure_is_reported_without_waiting(self):
        sync = self.sync
        with patch.object(sync, "_main_thread_id", -1):
            with patch.object(sync.idaapi, "execute_sync", return_value=-1):
                with self.assertRaisesRegex(sync.IDASyncError, "Failed to schedule"):
                    sync._sync_wrapper(lambda: None, wait_timeout=0.01)

    def test_missing_execute_sync_callback_times_out(self):
        sync = self.sync
        with patch.object(sync, "_main_thread_id", -1):
            with patch.object(sync.idaapi, "execute_sync", return_value=0):
                with patch.object(sync, "_EXECUTE_SYNC_WAIT_GRACE_SEC", 0.01):
                    with self.assertRaisesRegex(
                        sync.IDASyncError, "did not complete"
                    ):
                        sync._sync_wrapper(lambda: None, wait_timeout=0.01)


if __name__ == "__main__":
    unittest.main()
