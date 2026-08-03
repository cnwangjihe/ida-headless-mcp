import unittest

from ida_pro_mcp import idalib_pool_server


McpServer = idalib_pool_server._mcp_mod.McpServer


class McpCapabilityTests(unittest.TestCase):
    @staticmethod
    def _initialize(server):
        return server.registry.dispatch(
            {
                "jsonrpc": "2.0",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1"},
                },
                "id": 1,
            }
        )

    def test_resources_are_advertised_and_registered_by_default(self):
        server = McpServer("test")

        response = self._initialize(server)

        self.assertEqual(response["result"]["capabilities"]["resources"], {})
        self.assertIn("resources/list", server.registry.methods)
        self.assertIn("resources/templates/list", server.registry.methods)
        self.assertIn("resources/read", server.registry.methods)

    def test_resources_can_be_disabled(self):
        server = McpServer("test", resources_enabled=False)

        response = self._initialize(server)

        self.assertNotIn("resources", response["result"]["capabilities"])
        for method in (
            "resources/list",
            "resources/templates/list",
            "resources/read",
        ):
            with self.subTest(method=method):
                self.assertNotIn(method, server.registry.methods)
                rejected = server.registry.dispatch(
                    {"jsonrpc": "2.0", "method": method, "id": 2}
                )
                self.assertEqual(rejected["error"]["code"], -32601)


if __name__ == "__main__":
    unittest.main()
