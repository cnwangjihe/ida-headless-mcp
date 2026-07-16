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


if __name__ == "__main__":
    unittest.main()
