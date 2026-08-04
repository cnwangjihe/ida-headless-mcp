import unittest

from ida_pro_mcp import idalib_pool_server


McpServer = idalib_pool_server._mcp_mod.McpServer


class McpToolSafetyTests(unittest.TestCase):
    def setUp(self):
        self.server = McpServer("test")

        @self.server.tool
        def inspect_state() -> dict:
            return {"ok": True}

        @self.server.tool
        def run_script() -> dict:
            return {"ok": True}

        self.server.disabled_tools.add("run_script")

    def test_disabled_tool_is_hidden_from_tools_list(self):
        names = {
            tool["name"] for tool in self.server._mcp_tools_list()["tools"]
        }

        self.assertIn("inspect_state", names)
        self.assertNotIn("run_script", names)

    def test_disabled_tool_cannot_be_called_directly(self):
        result = self.server._mcp_tools_call("run_script")

        self.assertTrue(result["isError"])
        self.assertIn("disabled by safe mode", result["content"][0]["text"])

    def test_top_level_tool_error_is_marked_as_error(self):
        @self.server.tool
        def expected_failure() -> dict:
            return {"error": "input was rejected"}

        result = self.server._mcp_tools_call("expected_failure")

        self.assertTrue(result["isError"])
        self.assertEqual(
            result["structuredContent"], {"error": "input was rejected"}
        )

    def test_internal_exception_is_logged_but_not_returned(self):
        @self.server.tool
        def unexpected_failure() -> dict:
            raise RuntimeError("private traceback marker")

        with self.assertLogs("ida_mcp.rpc", level="ERROR") as captured:
            result = self.server._mcp_tools_call("unexpected_failure")

        text = result["content"][0]["text"]
        self.assertTrue(result["isError"])
        self.assertIn("Internal error (reference:", text)
        self.assertNotIn("private traceback marker", text)
        logs = "\n".join(captured.output)
        self.assertIn("private traceback marker", logs)
        self.assertIn("Traceback", logs)


if __name__ == "__main__":
    unittest.main()
