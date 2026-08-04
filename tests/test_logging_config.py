import io
import logging
import sys
import unittest
from contextlib import redirect_stderr
from unittest.mock import patch

from ida_pro_mcp import idalib_pool_server, server
from ida_pro_mcp.logging_config import (
    LOGGER_NAMESPACE,
    configure_runtime_logging,
    replace_runtime_log_handler,
)


class RuntimeLoggingConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.logger = logging.getLogger(LOGGER_NAMESPACE)
        self.old_handlers = list(self.logger.handlers)
        self.old_level = self.logger.level
        self.old_propagate = self.logger.propagate
        self.logger.handlers.clear()

    def tearDown(self):
        for handler in self.logger.handlers:
            handler.close()
        self.logger.handlers[:] = self.old_handlers
        self.logger.setLevel(self.old_level)
        self.logger.propagate = self.old_propagate

    def test_info_hides_debug_and_debug_enables_it(self):
        output = io.StringIO()
        component = logging.getLogger("ida_mcp.rpc")

        configure_runtime_logging("info", stream=output)
        component.debug("hidden request")
        component.info("session opened")
        self.assertNotIn("hidden request", output.getvalue())
        self.assertIn("INFO ida_mcp.rpc: session opened", output.getvalue())

        configure_runtime_logging("DEBUG", stream=output)
        component.debug("visible request")
        self.assertIn("DEBUG ida_mcp.rpc: visible request", output.getvalue())

    def test_runtime_handler_can_be_temporarily_replaced(self):
        output = io.StringIO()
        replacement_output = io.StringIO()
        component = logging.getLogger("ida_mcp.pool.session")
        configure_runtime_logging("info", stream=output)
        replacement = logging.StreamHandler(replacement_output)

        with replace_runtime_log_handler(replacement):
            component.info("inside TUI")
        component.info("after TUI")

        self.assertIn("inside TUI", replacement_output.getvalue())
        self.assertNotIn("inside TUI", output.getvalue())
        self.assertIn("after TUI", output.getvalue())


class CommandLineLogLevelTests(unittest.TestCase):
    @patch.object(idalib_pool_server.signal, "signal")
    @patch.object(idalib_pool_server, "build_dispatch")
    @patch.object(idalib_pool_server, "McpServer")
    @patch.object(idalib_pool_server, "PoolManager")
    @patch.object(idalib_pool_server, "configure_runtime_logging")
    def test_pool_accepts_case_insensitive_level_and_propagates_to_backend(
        self,
        configure_logging,
        pool_cls,
        mcp_cls,
        _build_dispatch,
        _signal,
    ):
        pool_cls.return_value.discover_tools.return_value = []

        with patch.object(
            sys,
            "argv",
            ["idalib-pool", "--log-level", "DEBUG"],
        ):
            idalib_pool_server.main()

        configure_logging.assert_called_once_with("debug")
        pool_cls.assert_called_once_with(
            runtime_dir=None,
            idalib_args=["--log-level", "debug"],
        )
        mcp_cls.return_value.stdio.assert_called_once_with()

    def test_pool_rejects_removed_verbose_flag(self):
        with (
            patch.object(sys, "argv", ["idalib-pool", "--verbose"]),
            redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as raised,
        ):
            idalib_pool_server.main()

        self.assertEqual(raised.exception.code, 2)

    @patch.object(server, "configure_runtime_logging")
    @patch.object(server.mcp, "stdio")
    def test_proxy_accepts_log_level(self, stdio, configure_logging):
        with patch.object(
            sys,
            "argv",
            ["ida-pro-mcp", "--log-level", "warning"],
        ):
            server.main()

        configure_logging.assert_called_once_with("warning")
        stdio.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
