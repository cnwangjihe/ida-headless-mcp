import os
import logging
import sys
import threading
import unittest
from contextlib import nullcontext
from unittest.mock import MagicMock, patch
from urllib.parse import urlparse

from ida_pro_mcp import idalib_pool_server

try:
    from ida_pro_mcp import idalib_server
except ImportError as exc:
    idalib_server = None
    IDALIB_IMPORT_ERROR = str(exc)
else:
    IDALIB_IMPORT_ERROR = ""


class PoolServerLifecycleTests(unittest.TestCase):
    def setUp(self):
        self._runtime_logger = logging.getLogger("ida_mcp")
        self._runtime_logging_state = (
            list(self._runtime_logger.handlers),
            self._runtime_logger.level,
            self._runtime_logger.propagate,
        )

    def tearDown(self):
        handlers, level, propagate = self._runtime_logging_state
        for handler in self._runtime_logger.handlers:
            if handler not in handlers:
                handler.close()
        self._runtime_logger.handlers[:] = handlers
        self._runtime_logger.setLevel(level)
        self._runtime_logger.propagate = propagate

    def test_explicit_ida_directory_overrides_environment(self):
        with patch.dict(os.environ, {"IDADIR": "/environment/ida"}):
            configured = idalib_pool_server.configure_ida_directory(
                "/explicit/ida"
            )

            self.assertEqual(configured, os.path.abspath("/explicit/ida"))
            self.assertEqual(os.environ["IDADIR"], configured)

    def test_ida_directory_falls_back_to_environment(self):
        with patch.dict(os.environ, {"IDADIR": "/environment/ida"}):
            configured = idalib_pool_server.configure_ida_directory(None)

            self.assertEqual(configured, "/environment/ida")
            self.assertEqual(os.environ["IDADIR"], "/environment/ida")

    @patch.object(idalib_pool_server, "PoolManager")
    def test_tui_rejects_stdio_before_creating_pool(self, pool_cls):
        with (
            patch.object(sys, "argv", ["idalib-pool", "--tui"]),
            patch.object(sys, "stderr"),
            self.assertRaises(SystemExit) as raised,
        ):
            idalib_pool_server.main()

        self.assertEqual(raised.exception.code, 2)
        pool_cls.assert_not_called()

    @patch.object(idalib_pool_server, "PoolManager")
    def test_tui_requires_interactive_terminal(self, pool_cls):
        stdin = MagicMock()
        stdout = MagicMock()
        stdin.isatty.return_value = False
        stdout.isatty.return_value = True
        with (
            patch.object(
                sys,
                "argv",
                [
                    "idalib-pool",
                    "--tui",
                    "--transport",
                    "http://127.0.0.1:8750",
                ],
            ),
            patch.object(sys, "stdin", stdin),
            patch.object(sys, "stdout", stdout),
            patch.object(sys, "stderr"),
            self.assertRaises(SystemExit) as raised,
        ):
            idalib_pool_server.main()

        self.assertEqual(raised.exception.code, 2)
        pool_cls.assert_not_called()

    def test_tui_runtime_bootstraps_server_and_stops_once(self):
        app = MagicMock()
        pool = MagicMock()
        mcp = MagicMock()
        handler = MagicMock()
        tools = [{"name": "get_functions"}]
        pool.discover_tools.return_value = tools
        runtime = idalib_pool_server.PoolTuiRuntime(
            app,
            pool,
            mcp,
            "http://127.0.0.1:8750",
            urlparse("http://127.0.0.1:8750"),
            None,
            handler,
        )

        with patch.object(idalib_pool_server, "build_dispatch") as dispatch:
            runtime._bootstrap()
            runtime.stop()
            runtime.stop()

        pool.discover_tools.assert_called_once_with()
        dispatch.assert_called_once_with(
            mcp,
            pool,
            output_cache=None,
            initial_tools=tools,
        )
        mcp.serve.assert_called_once_with(
            host="127.0.0.1",
            port=8750,
            background=True,
            request_handler=handler,
        )
        app.call_from_thread.assert_called_once_with(
            app.set_runtime_state,
            "READY",
            "http://127.0.0.1:8750",
        )
        mcp.stop.assert_called_once_with()
        pool.shutdown_all.assert_called_once_with()

    def test_tui_runtime_reports_startup_failure_without_listening(self):
        app = MagicMock()
        pool = MagicMock()
        mcp = MagicMock()
        pool.discover_tools.side_effect = RuntimeError("idalib unavailable")
        runtime = idalib_pool_server.PoolTuiRuntime(
            app,
            pool,
            mcp,
            "http://127.0.0.1:8750",
            urlparse("http://127.0.0.1:8750"),
            None,
            MagicMock(),
        )

        with patch.object(idalib_pool_server, "build_dispatch") as dispatch:
            runtime._bootstrap()

        dispatch.assert_not_called()
        mcp.serve.assert_not_called()
        state_call = app.call_from_thread.call_args.args
        self.assertIs(state_call[0], app.set_runtime_state)
        self.assertEqual(state_call[1], "FAILED")
        self.assertIn("idalib unavailable", state_call[2])

    def test_tui_runtime_does_not_listen_after_stop_during_discovery(self):
        app = MagicMock()
        pool = MagicMock()
        mcp = MagicMock()
        discovery_started = threading.Event()
        allow_discovery = threading.Event()

        def discover():
            discovery_started.set()
            allow_discovery.wait(1)
            return []

        pool.discover_tools.side_effect = discover
        runtime = idalib_pool_server.PoolTuiRuntime(
            app,
            pool,
            mcp,
            "http://127.0.0.1:8750",
            urlparse("http://127.0.0.1:8750"),
            None,
            MagicMock(),
        )
        runtime.start()
        self.assertTrue(discovery_started.wait(1))
        allow_discovery.set()
        runtime.stop()

        mcp.serve.assert_not_called()
        pool.shutdown_all.assert_called_once_with()

    @patch.object(idalib_pool_server.signal, "signal")
    @patch.object(idalib_pool_server, "_prepare_tui_process_spawning")
    @patch.object(idalib_pool_server, "replace_runtime_log_handler")
    @patch.object(idalib_pool_server, "build_pool_handler_class")
    @patch.object(idalib_pool_server, "PoolTuiRuntime")
    @patch.object(idalib_pool_server, "PoolTuiApp")
    @patch.object(idalib_pool_server, "BufferedLogHandler")
    @patch.object(idalib_pool_server, "AdminEventBus")
    @patch.object(idalib_pool_server, "McpServer")
    @patch.object(idalib_pool_server, "PoolManager")
    def test_tui_cli_wires_events_and_defers_bootstrap_until_mount(
        self,
        pool_cls,
        mcp_cls,
        event_bus_cls,
        log_handler_cls,
        app_cls,
        runtime_cls,
        build_handler,
        replace_handler,
        prepare_spawning,
        signal_mock,
    ):
        pool = pool_cls.return_value
        mcp = mcp_cls.return_value
        event_bus = event_bus_cls.return_value
        app = app_cls.return_value
        runtime = runtime_cls.return_value
        replace_handler.return_value = nullcontext()

        def run_app():
            self.assertIs(mcp.admin_event_sink, event_bus.publish)
            self.assertIs(pool.admin_event_sink, event_bus.publish)
            runtime.start.assert_not_called()
            app.startup_callback()

        app.run.side_effect = run_app
        stdin = MagicMock()
        stdout = MagicMock()
        stdin.isatty.return_value = True
        stdout.isatty.return_value = True
        with (
            patch.object(
                sys,
                "argv",
                [
                    "idalib-pool",
                    "--tui",
                    "--transport",
                    "http://127.0.0.1:8750",
                ],
            ),
            patch.object(sys, "stdin", stdin),
            patch.object(sys, "stdout", stdout),
        ):
            idalib_pool_server.main()

        pool.discover_tools.assert_not_called()
        app_cls.assert_called_once_with(
            event_bus,
            log_handler_cls.return_value,
            mcp_server=mcp,
            pool_manager=pool,
        )
        runtime.start.assert_called_once_with()
        runtime.stop.assert_called_once_with()
        prepare_spawning.assert_called_once_with()
        self.assertIsNone(mcp.admin_event_sink)
        self.assertIsNone(pool.admin_event_sink)

    @patch.object(idalib_pool_server.signal, "signal")
    @patch.object(idalib_pool_server, "build_dispatch")
    @patch.object(idalib_pool_server, "McpServer")
    @patch.object(idalib_pool_server, "PoolManager")
    def test_stdio_eof_always_shuts_down_pool(
        self, pool_cls, mcp_cls, build_dispatch, signal_mock
    ):
        pool = pool_cls.return_value
        mcp = mcp_cls.return_value
        initial_tools = [{"name": "get_functions", "inputSchema": {}}]
        pool.discover_tools.return_value = initial_tools

        with patch.object(sys, "argv", ["idalib-pool"]):
            idalib_pool_server.main()

        pool_cls.assert_called_once_with(
            runtime_dir=None,
            idalib_args=["--log-level", "info"],
        )
        mcp_cls.assert_called_once_with("ida-pro-mcp", resources_enabled=False)
        self.assertEqual(mcp.http_session_ttl_seconds, 3600)
        pool.discover_tools.assert_called_once_with()
        build_dispatch.assert_called_once_with(
            mcp,
            pool,
            output_cache=None,
            initial_tools=initial_tools,
        )
        mcp.stdio.assert_called_once_with()
        pool.shutdown_all.assert_called_once_with()

    @patch.object(idalib_pool_server.signal, "signal")
    @patch.object(idalib_pool_server, "build_dispatch")
    @patch.object(idalib_pool_server, "McpServer")
    @patch.object(idalib_pool_server, "PoolManager")
    def test_backend_startup_failure_prevents_listening(
        self, pool_cls, mcp_cls, build_dispatch, signal_mock
    ):
        pool = pool_cls.return_value
        pool.discover_tools.side_effect = RuntimeError("idalib.dll unavailable")

        with (
            patch.object(sys, "argv", ["idalib-pool"]),
            patch.object(sys, "stderr"),
            self.assertRaises(SystemExit) as raised,
        ):
            idalib_pool_server.main()

        self.assertEqual(raised.exception.code, 1)
        build_dispatch.assert_not_called()
        mcp_cls.return_value.stdio.assert_not_called()
        mcp_cls.return_value.serve.assert_not_called()
        pool.shutdown_all.assert_called_once_with()


@unittest.skipIf(
    idalib_server is None,
    f"idalib is unavailable in this test environment: {IDALIB_IMPORT_ERROR}",
)
class IdalibServerLifecycleTests(unittest.TestCase):
    def setUp(self):
        self._runtime_logger = logging.getLogger("ida_mcp")
        self._runtime_logging_state = (
            list(self._runtime_logger.handlers),
            self._runtime_logger.level,
            self._runtime_logger.propagate,
        )
        self.old_session_id = idalib_server._current_session_id
        self.old_input_path = idalib_server._current_input_path
        self.old_idb_path = idalib_server._current_idb_path
        self.old_disabled_tools = set(idalib_server.MCP_SERVER.disabled_tools)

    def tearDown(self):
        handlers, level, propagate = self._runtime_logging_state
        for handler in self._runtime_logger.handlers:
            if handler not in handlers:
                handler.close()
        self._runtime_logger.handlers[:] = handlers
        self._runtime_logger.setLevel(level)
        self._runtime_logger.propagate = propagate
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
            patch.object(
                idalib_server.idapro,
                "enable_console_messages",
            ) as enable_console_messages,
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
            enable_console_messages.assert_called_once_with(False)
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
                idalib_args=["--log-level", "debug", "--safe"],
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
