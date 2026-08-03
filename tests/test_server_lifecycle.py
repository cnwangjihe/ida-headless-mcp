import sys
import unittest
from unittest.mock import MagicMock, patch

from ida_pro_mcp import idalib_pool_server

try:
    from ida_pro_mcp import idalib_server
except ImportError as exc:
    idalib_server = None
    IDALIB_IMPORT_ERROR = str(exc)
else:
    IDALIB_IMPORT_ERROR = ""


class PoolServerLifecycleTests(unittest.TestCase):
    @patch.object(idalib_pool_server.signal, "signal")
    @patch.object(idalib_pool_server, "build_dispatch")
    @patch.object(idalib_pool_server, "McpServer")
    @patch.object(idalib_pool_server, "PoolManager")
    def test_stdio_eof_always_shuts_down_pool(
        self, pool_cls, mcp_cls, build_dispatch, signal_mock
    ):
        pool = pool_cls.return_value
        mcp = mcp_cls.return_value

        with patch.object(sys, "argv", ["idalib-pool"]):
            idalib_pool_server.main()

        pool_cls.assert_called_once_with(runtime_dir=None, idalib_args=[])
        mcp.stdio.assert_called_once_with()
        pool.shutdown_all.assert_called_once_with()


@unittest.skipIf(
    idalib_server is None,
    f"idalib is unavailable in this test environment: {IDALIB_IMPORT_ERROR}",
)
class IdalibServerLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.old_session_id = idalib_server._current_session_id
        self.old_input_path = idalib_server._current_input_path
        self.old_idb_path = idalib_server._current_idb_path
        self.old_disabled_tools = set(idalib_server.MCP_SERVER.disabled_tools)

    def tearDown(self):
        idalib_server._current_session_id = self.old_session_id
        idalib_server._current_input_path = self.old_input_path
        idalib_server._current_idb_path = self.old_idb_path
        idalib_server.MCP_SERVER.disabled_tools.clear()
        idalib_server.MCP_SERVER.disabled_tools.update(self.old_disabled_tools)

    def test_open_database_rejects_replacing_an_active_session(self):
        with (
            patch.object(idalib_server.idapro, "close_database") as close_database,
            patch.object(idalib_server.idapro, "open_database") as open_database,
        ):
            idalib_server._current_session_id = "active-session"

            with self.assertRaisesRegex(RuntimeError, "start a new backend"):
                idalib_server._open_database("/tmp/other.bin")

            open_database.assert_not_called()
            close_database.assert_not_called()

    def test_ipc_server_return_saves_and_closes_database(self):
        with (
            patch.object(idalib_server, "BackendIpcServer") as server_cls,
            patch.object(idalib_server.idapro, "enable_console_messages"),
            patch.object(idalib_server.idapro, "close_database") as close_database,
            patch.object(
                idalib_server.ida_loader,
                "save_database",
                return_value=True,
            ) as save_database,
            patch.object(
                idalib_server.ida_loader,
                "get_path",
                return_value="/tmp/test.i64",
            ),
        ):
            idalib_server._current_session_id = "test-session"
            idalib_server._current_input_path = "/tmp/test.bin"
            idalib_server._current_idb_path = "/tmp/test.i64"

            idalib_server.run_ipc_backend(
                MagicMock(),
                MagicMock(),
                idalib_args=[],
            )

            server_cls.return_value.serve.assert_called_once()
            save_database.assert_called_once_with("/tmp/test.i64", 0)
            close_database.assert_called_once_with()
            self.assertIsNone(idalib_server._current_session_id)

    def test_ipc_backend_configures_and_serves_inherited_connections(self):
        with (
            patch.object(idalib_server, "BackendIpcServer") as server_cls,
            patch.object(
                idalib_server.idapro,
                "enable_console_messages",
            ) as enable_console_messages,
        ):
            rpc_connection = MagicMock()
            control_connection = MagicMock()

            idalib_server.run_ipc_backend(
                rpc_connection,
                control_connection,
                idalib_args=["--verbose", "--safe"],
            )

            enable_console_messages.assert_called_once_with(True)
            server_cls.assert_called_once_with(
                rpc_connection,
                control_connection,
                dispatch=idalib_server._dispatch_ipc_request,
                cancel_pending=idalib_server.cancel_all_pending_requests,
            )
            server_cls.return_value.serve.assert_called_once()
            ready_fields = server_cls.return_value.serve.call_args.kwargs["ready_fields"]
            self.assertEqual(ready_fields["pid"], idalib_server.os.getpid())
            self.assertTrue(
                idalib_server.MCP_UNSAFE <= idalib_server.MCP_SERVER.disabled_tools
            )

    def test_ipc_dispatch_sets_and_clears_transport_context(self):
        with patch.object(idalib_server.MCP_SERVER.registry, "dispatch") as dispatch:
            def inspect_context(request):
                self.assertEqual(
                    idalib_server.MCP_SERVER.get_current_transport_session_id(),
                    "backend:default",
                )
                self.assertEqual(
                    idalib_server.MCP_SERVER._protocol_version.data,
                    idalib_server.LATEST_MCP_PROTOCOL_VERSION,
                )
                return {"jsonrpc": "2.0", "result": {}, "id": request["id"]}

            dispatch.side_effect = inspect_context

            response = idalib_server._dispatch_ipc_request(
                {"jsonrpc": "2.0", "method": "ping", "id": 1}
            )

            self.assertEqual(response["id"], 1)
            self.assertIsNone(
                idalib_server.MCP_SERVER.get_current_transport_session_id()
            )


if __name__ == "__main__":
    unittest.main()
