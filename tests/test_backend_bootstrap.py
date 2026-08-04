import unittest
from unittest.mock import MagicMock, patch

from ida_pro_mcp import backend_bootstrap


class BackendBootstrapTests(unittest.TestCase):
    @patch.object(backend_bootstrap, "configure_runtime_logging")
    @patch.object(backend_bootstrap.importlib, "import_module")
    @patch.object(backend_bootstrap, "_redirect_output")
    def test_redirects_output_before_importing_ida_backend(
        self,
        redirect_output,
        import_module,
        configure_logging,
    ):
        events = []
        log_file = MagicMock()
        rpc_connection = MagicMock()
        control_connection = MagicMock()
        idalib_server = MagicMock()
        redirect_output.side_effect = lambda path: events.append(
            ("redirect", path)
        ) or log_file
        import_module.side_effect = lambda name: events.append(
            ("import", name)
        ) or idalib_server
        configure_logging.side_effect = lambda level: events.append(
            ("logging", level)
        )

        backend_bootstrap.run_backend_process(
            rpc_connection,
            control_connection,
            "/tmp/backend.log",
            ["--safe"],
        )

        self.assertEqual(
            events,
            [
                ("redirect", "/tmp/backend.log"),
                ("logging", "info"),
                ("import", "ida_pro_mcp.idalib_server"),
            ],
        )
        idalib_server.run_ipc_backend.assert_called_once_with(
            rpc_connection,
            control_connection,
            idalib_args=["--safe"],
        )
        rpc_connection.close.assert_called_once_with()
        control_connection.close.assert_called_once_with()
        log_file.flush.assert_called_once_with()

    @patch.object(backend_bootstrap, "configure_runtime_logging")
    @patch.object(backend_bootstrap.importlib, "import_module")
    @patch.object(backend_bootstrap, "_redirect_output")
    def test_configures_requested_log_level_before_backend_import(
        self,
        redirect_output,
        import_module,
        configure_logging,
    ):
        redirect_output.return_value = MagicMock()

        backend_bootstrap.run_backend_process(
            MagicMock(),
            MagicMock(),
            "/tmp/backend.log",
            ["--log-level", "debug"],
        )

        configure_logging.assert_called_once_with("debug")


if __name__ == "__main__":
    unittest.main()
