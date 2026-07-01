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

    def test_http_module_does_not_filter_tools_at_import_time(self):
        tree = ast.parse(HTTP_MODULE.read_text(), filename=str(HTTP_MODULE))
        for node in tree.body:
            if not isinstance(node, ast.Assign):
                continue
            target_names = [
                target.id
                for target in node.targets
                if isinstance(target, ast.Name)
            ]
            if "ORIGINAL_TOOLS" not in target_names:
                continue
            self.assertFalse(
                isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Name)
                and node.value.func.id == "handle_enabled_tools",
                "http.py must not apply enabled_tools filtering during import",
            )


if __name__ == "__main__":
    unittest.main()
