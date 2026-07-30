import ast
import unittest
from pathlib import Path


PLUGIN_LOADER = Path(__file__).resolve().parents[1] / "src" / "ida_pro_mcp" / "ida_mcp.py"
HTTP_MODULE = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "ida_pro_mcp"
    / "ida_mcp"
    / "http.py"
)


class TestIdaPluginLoaderStatic(unittest.TestCase):
    def test_output_download_route_enforces_authentication_and_host(self):
        tree = ast.parse(HTTP_MODULE.read_text(), filename=str(HTTP_MODULE))
        handler = next(
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef)
            and node.name == "IdaMcpHttpRequestHandler"
        )

        method = next(
            node
            for node in handler.body
            if isinstance(node, ast.FunctionDef) and node.name == "do_GET"
        )
        call_names = {
            node.func.attr
            for node in ast.walk(method)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
        }
        self.assertIn("_check_auth", call_names)
        self.assertIn("_check_host", call_names)

    def test_local_server_updates_output_download_base_url(self):
        tree = ast.parse(PLUGIN_LOADER.read_text(), filename=str(PLUGIN_LOADER))
        start_local_server = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef)
            and node.name == "start_local_server"
        )
        call_names = {
            node.func.id
            for node in ast.walk(start_local_server)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
        }

        self.assertIn("set_download_base_url", call_names)

    def test_gui_web_config_routes_are_removed(self):
        source = HTTP_MODULE.read_text()
        tree = ast.parse(source, filename=str(HTTP_MODULE))
        handler = next(
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef)
            and node.name == "IdaMcpHttpRequestHandler"
        )

        method_names = {
            node.name for node in handler.body if isinstance(node, ast.FunctionDef)
        }
        self.assertNotIn("do_POST", method_names)
        self.assertNotIn('"/config"', source)
        self.assertNotIn('"/config.html"', source)

    def test_plugin_loader_uses_side_effect_free_config_module(self):
        """Pool mode must not import ida_mcp.http just to read config.

        Importing ida_mcp.http used to apply the local enabled_tools filter to
        the GUI registry, which can make pool-discovered tools fail with Method
        not found.
        """
        tree = ast.parse(PLUGIN_LOADER.read_text(), filename=str(PLUGIN_LOADER))
        imported_modules = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if node.level:
                    module = "." * node.level + module
                imported_modules.append(module)

        self.assertNotIn("ida_mcp.http", imported_modules)
        self.assertNotIn(".ida_mcp.http", imported_modules)

    def test_pool_connection_resets_registry_and_disables_proxy(self):
        tree = ast.parse(PLUGIN_LOADER.read_text(), filename=str(PLUGIN_LOADER))

        def stmt_has_call(stmt, name: str) -> bool:
            return any(
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == name
                for node in ast.walk(stmt)
            )

        connect_pool = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == "connect_pool"
        )
        unload_indexes = [
            idx
            for idx, stmt in enumerate(connect_pool.body)
            if any(
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "unload_package"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and node.args[0].value == "ida_mcp"
                for node in ast.walk(stmt)
            )
        ]
        connector_indexes = [
            idx
            for idx, stmt in enumerate(connect_pool.body)
            if stmt_has_call(stmt, "PoolConnector")
        ]
        self.assertTrue(
            unload_indexes,
            "connect_pool must reset ida_mcp before pool use",
        )
        self.assertTrue(
            connector_indexes,
            "connect_pool must instantiate PoolConnector",
        )
        self.assertLess(min(unload_indexes), min(connector_indexes))
        pool_connector_calls = [
            node
            for node in ast.walk(connect_pool)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "PoolConnector"
        ]
        for call in pool_connector_calls:
            self.assertGreaterEqual(
                len(call.args),
                4,
                "PoolConnector calls must receive the preloaded MCP server",
            )
            self.assertIsInstance(call.args[3], ast.Name)
            self.assertEqual(call.args[3].id, "MCP_SERVER")

        pool_connector_class = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.ClassDef) and node.name == "PoolConnector"
        )
        pool_connector_init = next(
            node
            for node in pool_connector_class.body
            if isinstance(node, ast.FunctionDef) and node.name == "__init__"
        )
        init_arg_names = [arg.arg for arg in pool_connector_init.args.args]
        self.assertIn(
            "mcp_server",
            init_arg_names,
            "PoolConnector must receive a preloaded MCP server from the main thread",
        )
        ws_connect_calls = [
            node
            for node in ast.walk(pool_connector_init)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "ws_connect"
        ]
        self.assertTrue(ws_connect_calls, "PoolConnector must call ws_connect")
        proxy_keywords = [
            kw
            for kw in ws_connect_calls[0].keywords
            if kw.arg == "proxy"
        ]
        self.assertTrue(proxy_keywords, "ws_connect must set proxy=None")
        self.assertIsNone(proxy_keywords[0].value.value)
        max_size_keywords = [
            kw
            for kw in ws_connect_calls[0].keywords
            if kw.arg == "max_size"
        ]
        self.assertTrue(
            max_size_keywords,
            "PoolConnector must raise the WebSocket message size limit",
        )

    def test_pool_listener_does_not_import_ida_mcp_from_background_thread(self):
        tree = ast.parse(PLUGIN_LOADER.read_text(), filename=str(PLUGIN_LOADER))
        pool_connector_class = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.ClassDef) and node.name == "PoolConnector"
        )
        listen = next(
            node
            for node in pool_connector_class.body
            if isinstance(node, ast.FunctionDef) and node.name == "_listen"
        )

        imported_modules = []
        for node in ast.walk(listen):
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if node.level:
                    module = "." * node.level + module
                imported_modules.append(module)

        self.assertNotIn("ida_mcp", imported_modules)
        self.assertNotIn(".ida_mcp", imported_modules)

    def test_pool_connector_notifies_plugin_on_unexpected_disconnect(self):
        tree = ast.parse(PLUGIN_LOADER.read_text(), filename=str(PLUGIN_LOADER))
        pool_connector_class = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.ClassDef) and node.name == "PoolConnector"
        )
        pool_connector_init = next(
            node
            for node in pool_connector_class.body
            if isinstance(node, ast.FunctionDef) and node.name == "__init__"
        )
        init_arg_names = [arg.arg for arg in pool_connector_init.args.args]
        self.assertIn("on_disconnect", init_arg_names)

        listen = next(
            node
            for node in pool_connector_class.body
            if isinstance(node, ast.FunctionDef) and node.name == "_listen"
        )
        on_disconnect_calls = [
            node
            for node in ast.walk(listen)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "_on_disconnect"
        ]
        self.assertTrue(
            on_disconnect_calls,
            "_listen must notify MCP when the pool WebSocket closes",
        )
        self.assertTrue(
            any(
                isinstance(node, ast.Attribute)
                and node.attr == "_disconnecting"
                for node in ast.walk(listen)
            ),
            "manual disconnects must not be reported as server loss",
        )

        disconnect = next(
            node
            for node in pool_connector_class.body
            if isinstance(node, ast.FunctionDef) and node.name == "disconnect"
        )
        manual_disconnect_assignments = [
            node
            for node in ast.walk(disconnect)
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Attribute)
                and target.attr == "_disconnecting"
                for target in node.targets
            )
        ]
        self.assertTrue(manual_disconnect_assignments)

    def test_connect_pool_passes_disconnect_callback_to_connector(self):
        tree = ast.parse(PLUGIN_LOADER.read_text(), filename=str(PLUGIN_LOADER))
        connect_pool = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == "connect_pool"
        )
        pool_connector_calls = [
            node
            for node in ast.walk(connect_pool)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "PoolConnector"
        ]
        self.assertTrue(pool_connector_calls)
        for call in pool_connector_calls:
            callbacks = [
                kw.value
                for kw in call.keywords
                if kw.arg == "on_disconnect"
            ]
            self.assertTrue(callbacks)
            self.assertIsInstance(callbacks[0], ast.Attribute)
            self.assertEqual(callbacks[0].attr, "_handle_pool_disconnected")

        mcp_class = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.ClassDef) and node.name == "MCP"
        )
        handler = next(
            node
            for node in mcp_class.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "_handle_pool_disconnected"
        )
        clears_pool_connector = any(
            isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Attribute)
                and target.attr == "pool_connector"
                for target in node.targets
            )
            and isinstance(node.value, ast.Constant)
            and node.value.value is None
            for node in ast.walk(handler)
        )
        self.assertTrue(clears_pool_connector)
        self.assertTrue(
            any(
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "update_menu_state"
                for node in ast.walk(handler)
            )
        )

    def test_http_module_does_not_filter_tools(self):
        tree = ast.parse(HTTP_MODULE.read_text(), filename=str(HTTP_MODULE))
        function_names = {
            node.name for node in tree.body if isinstance(node, ast.FunctionDef)
        }
        assigned_names = {
            target.id
            for node in tree.body
            if isinstance(node, ast.Assign)
            for target in node.targets
            if isinstance(target, ast.Name)
        }
        self.assertNotIn("handle_enabled_tools", function_names)
        self.assertNotIn("ensure_enabled_tools_initialized", function_names)
        self.assertNotIn("ORIGINAL_TOOLS", assigned_names)


if __name__ == "__main__":
    unittest.main()
