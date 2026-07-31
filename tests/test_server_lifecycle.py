import sys
import unittest
from unittest.mock import MagicMock, patch

from ida_pro_mcp import idalib_pool_server
from ida_pro_mcp import idalib_server


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

        mcp.stdio.assert_called_once_with()
        pool.shutdown_all.assert_called_once_with()

class IdalibServerLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.old_session_id = idalib_server._current_session_id
        self.old_input_path = idalib_server._current_input_path
        self.old_idb_path = idalib_server._current_idb_path

    def tearDown(self):
        idalib_server._current_session_id = self.old_session_id
        idalib_server._current_input_path = self.old_input_path
        idalib_server._current_idb_path = self.old_idb_path

    @patch.object(idalib_server.idapro, "close_database")
    @patch.object(idalib_server.idapro, "open_database")
    def test_open_database_rejects_replacing_an_active_session(
        self, open_database, close_database
    ):
        idalib_server._current_session_id = "active-session"

        with self.assertRaisesRegex(RuntimeError, "start a new backend"):
            idalib_server._open_database("/tmp/other.bin")

        open_database.assert_not_called()
        close_database.assert_not_called()

    @patch.object(idalib_server.signal, "signal")
    @patch.object(idalib_server.idapro, "enable_console_messages")
    @patch.object(idalib_server.idapro, "close_database")
    @patch.object(idalib_server.ida_loader, "save_database", return_value=True)
    @patch.object(idalib_server.ida_loader, "get_path", return_value="/tmp/test.i64")
    @patch.object(idalib_server.MCP_SERVER, "serve")
    def test_normal_server_return_saves_and_closes_database(
        self,
        serve,
        get_path,
        save_database,
        close_database,
        enable_console_messages,
        signal_mock,
    ):
        idalib_server._current_session_id = "test-session"
        idalib_server._current_input_path = "/tmp/test.bin"
        idalib_server._current_idb_path = "/tmp/test.i64"

        with patch.object(
            sys, "argv", ["idalib-server", "--unix-socket", "/tmp/test.sock"]
        ):
            idalib_server.main()

        save_database.assert_called_once_with("/tmp/test.i64", 0)
        close_database.assert_called_once_with()
        self.assertIsNone(idalib_server._current_session_id)


if __name__ == "__main__":
    unittest.main()
