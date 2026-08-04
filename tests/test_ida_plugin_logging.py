import importlib.util
import io
import logging
import sys
import types
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import MagicMock, patch


PLUGIN_LOADER = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "ida_pro_mcp"
    / "ida_mcp.py"
)


class _FakeForm:
    FT_DEC = 0

    class StringInput:
        def __init__(self, value=""):
            self.value = value

    class NumericInput:
        def __init__(self, value=0, tp=0):
            self.value = value

    def __init__(self, *_args, **_kwargs):
        pass


class _FakeActionHandler:
    def __init__(self):
        pass


class _FakePlugin:
    pass


class _FakeHooks:
    def hook(self):
        self.hooked = True

    def unhook(self):
        self.hooked = False


class _FakeActionDescription:
    def __init__(
        self,
        name,
        label,
        handler,
        shortcut=None,
        tooltip=None,
        icon=-1,
        flags=0,
    ):
        self.name = name
        self.label = label
        self.handler = handler
        self.shortcut = shortcut
        self.tooltip = tooltip
        self.icon = icon
        self.flags = flags


def _load_plugin_loader():
    registered_actions = {}
    idaapi = types.ModuleType("idaapi")
    idaapi.Form = _FakeForm
    idaapi.action_handler_t = _FakeActionHandler
    idaapi.plugin_t = _FakePlugin
    idaapi.PLUGIN_KEEP = 1
    idaapi.PLUGIN_HIDE = 2
    idaapi.AST_ENABLE = 1
    idaapi.AST_DISABLE = 0
    idaapi.AST_ENABLE_ALWAYS = 2
    idaapi.SETMENU_APP = 0

    ida_kernwin = types.ModuleType("ida_kernwin")
    ida_kernwin.UI_Hooks = _FakeHooks
    ida_kernwin.action_desc_t = _FakeActionDescription
    ida_kernwin.AST_ENABLE = 1
    ida_kernwin.AST_DISABLE = 0
    ida_kernwin.ADF_CHECKABLE = 0x20
    ida_kernwin.register_action = lambda desc: registered_actions.setdefault(
        desc.name, desc
    ) is desc
    ida_kernwin.unregister_action = MagicMock(return_value=True)
    ida_kernwin.update_action_state = MagicMock(return_value=True)
    ida_kernwin.update_action_checked = MagicMock(return_value=True)
    ida_kernwin.create_menu = MagicMock(return_value=True)
    ida_kernwin.delete_menu = MagicMock(return_value=True)
    ida_kernwin.attach_action_to_menu = MagicMock(return_value=True)
    ida_kernwin.detach_action_from_menu = MagicMock(return_value=True)

    fake_modules = {
        "idaapi": idaapi,
        "ida_kernwin": ida_kernwin,
        "ida_nalt": types.ModuleType("ida_nalt"),
        "ida_loader": types.ModuleType("ida_loader"),
    }
    spec = importlib.util.spec_from_file_location(
        "ida_mcp_plugin_loader_under_test",
        PLUGIN_LOADER,
    )
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, fake_modules):
        assert spec.loader is not None
        spec.loader.exec_module(module)
    return module, ida_kernwin, registered_actions


class IdaPluginLoggingTests(unittest.TestCase):
    def setUp(self):
        self.namespace_logger = logging.getLogger("ida_mcp")
        self.old_handlers = list(self.namespace_logger.handlers)
        self.old_level = self.namespace_logger.level
        self.old_propagate = self.namespace_logger.propagate

    def tearDown(self):
        for handler in list(self.namespace_logger.handlers):
            if handler not in self.old_handlers:
                self.namespace_logger.removeHandler(handler)
                handler.close()
        self.namespace_logger.handlers[:] = self.old_handlers
        self.namespace_logger.setLevel(self.old_level)
        self.namespace_logger.propagate = self.old_propagate

    def test_verbose_action_toggles_entire_namespace(self):
        module, ida_kernwin, registered_actions = _load_plugin_loader()
        self.namespace_logger.setLevel(logging.DEBUG)
        output = io.StringIO()
        plugin = module.MCP()

        with redirect_stderr(output):
            plugin.init()
            self.assertEqual(self.namespace_logger.level, logging.INFO)
            self.assertFalse(plugin.verbose_logging)

            action = registered_actions[module.VERBOSE_LOGGING_ACTION_ID]
            self.assertEqual(action.flags, ida_kernwin.ADF_CHECKABLE)

            action.handler.activate(None)
            logging.getLogger("ida_mcp.rpc").debug("debug request visible")
            self.assertEqual(self.namespace_logger.level, logging.DEBUG)
            self.assertTrue(plugin.verbose_logging)

            action.handler.activate(None)
            logging.getLogger("ida_mcp.rpc").debug("debug request hidden")
            self.assertEqual(self.namespace_logger.level, logging.INFO)
            self.assertFalse(plugin.verbose_logging)

            plugin.term()

        text = output.getvalue()
        self.assertIn("Plugin loaded", text)
        self.assertIn("Verbose logging enabled", text)
        self.assertIn("debug request visible", text)
        self.assertNotIn("debug request hidden", text)
        ida_kernwin.update_action_checked.assert_any_call(
            module.VERBOSE_LOGGING_ACTION_ID,
            True,
        )
        self.assertNotIn(plugin._logging_handler, self.namespace_logger.handlers)

    def test_each_plugin_start_resets_verbose_to_info(self):
        module, _ida_kernwin, _registered_actions = _load_plugin_loader()
        plugin = module.MCP()

        with redirect_stderr(io.StringIO()):
            plugin.init()
            plugin.set_verbose_logging(True)
            plugin.term()

            restarted = module.MCP()
            restarted.init()
            self.assertFalse(restarted.verbose_logging)
            self.assertEqual(self.namespace_logger.level, logging.INFO)
            restarted.term()


if __name__ == "__main__":
    unittest.main()
