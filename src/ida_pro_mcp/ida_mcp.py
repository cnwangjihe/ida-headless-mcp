"""IDA Pro MCP Plugin Loader

This file serves as the entry point for IDA Pro's plugin system.
It loads the actual implementation from the ida_mcp package.
"""

import json
import os
import sys
import threading
import idaapi
import ida_kernwin
import ida_nalt
import ida_loader
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from . import ida_mcp


def ensure_plugin_dir_on_path():
    """Make the sibling ida_mcp package importable from IDA's plugin loader."""
    plugin_dir = os.path.dirname(__file__)
    if plugin_dir not in sys.path:
        sys.path.insert(0, plugin_dir)


def unload_package(package_name: str):
    """Remove every module that belongs to the package from sys.modules."""
    to_remove = [
        mod_name
        for mod_name in sys.modules
        if mod_name == package_name or mod_name.startswith(package_name + ".")
    ]
    for mod_name in to_remove:
        del sys.modules[mod_name]


CONFIG_ACTION_ID = "mcp:configure"
CONFIG_ACTION_LABEL = "MCP Configuration"
LOCAL_SERVER_ACTION_ID = "mcp:local_server"
LOCAL_SERVER_ACTION_LABEL = "MCP Local Server"


class MCPConfigForm(idaapi.Form):
    """Form to configure MCP server host and port."""

    def __init__(self, host: str, port: int):
        form_str = r"""STARTITEM 0
MCP Server Configuration

<Host:{host}>
<Port:{port}>
"""
        super().__init__(
            form_str,
            {
                "host": idaapi.Form.StringInput(value=host),
                "port": idaapi.Form.NumericInput(value=port, tp=idaapi.Form.FT_DEC),
            },
        )


class MCPConfigHandler(idaapi.action_handler_t):
    def __init__(self, plugin: "MCP"):
        idaapi.action_handler_t.__init__(self)
        self.plugin = plugin

    def activate(self, ctx):
        old_host = self.plugin.host
        old_port = self.plugin.port

        form = MCPConfigForm(self.plugin.host, self.plugin.port)
        form.Compile()
        ok = form.Execute()
        if ok != 1:
            form.Free()
            return 0

        host = form.host.value
        port = form.port.value
        form.Free()

        if port < 1 or port > 65535:
            print(f"[MCP] Invalid port: {port}")
            return 0

        if host == old_host and port == old_port:
            print(f"[MCP] Configuration unchanged: {host}:{port}")
            return 1

        self.plugin.host = host
        self.plugin.port = port
        print(f"[MCP] Configuration updated: {host}:{port}")

        # Apply new endpoint immediately if the server is running.
        if self.plugin.mcp is not None:
            print("[MCP] Applying configuration change without manual restart...")
            self.plugin.start_local_server()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class MCPUIHooks(ida_kernwin.UI_Hooks):
    """Defers menu attachment until the UI is fully ready."""

    def ready_to_run(self):
        ida_kernwin.attach_action_to_menu(
            "Edit/Plugins/", CONFIG_ACTION_ID, idaapi.SETMENU_APP
        )
        ida_kernwin.attach_action_to_menu(
            "Edit/Plugins/", LOCAL_SERVER_ACTION_ID, idaapi.SETMENU_APP
        )
        self.unhook()


POOL_ACTION_LABEL = "MCP Pool"


class PoolConnector:
    """Manages WebSocket connection from plugin to a pool server."""

    def __init__(self, pool_url: str, input_path: str, idb_path: str,
                 session_name: str, auth_token: str = "",
                 allow_duplicate_input: bool = False):
        from websockets.sync.client import connect as ws_connect

        ws_url = pool_url.replace("http://", "ws://").replace("https://", "wss://")
        ws_url = ws_url.rstrip("/") + "/pool/ws"
        headers = {}
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"

        self.ws = ws_connect(ws_url, additional_headers=headers)
        self._alive = True
        self._agent_count = 0
        self._agent_count_event = threading.Event()

        self.ws.send(json.dumps({
            "type": "register",
            "input_path": input_path,
            "idb_path": idb_path,
            "session_id": session_name,
            "allow_duplicate_input": allow_duplicate_input,
        }))
        raw = self.ws.recv()
        self._reg_response = json.loads(raw)

        if not self._reg_response.get("success"):
            self.ws.close()
            self._alive = False
            return

        self.session_id = self._reg_response["session"]["session_id"]
        self._thread = threading.Thread(target=self._listen, daemon=True)
        self._thread.start()

    @property
    def registration_response(self) -> dict:
        return self._reg_response

    def _listen(self):
        while self._alive:
            try:
                raw = self.ws.recv()
            except Exception:
                break
            try:
                msg = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                continue

            if msg.get("type") == "agent_count":
                self._agent_count = msg.get("active_agents", 0)
                self._agent_count_event.set()
                continue

            if TYPE_CHECKING:
                from .ida_mcp.rpc import MCP_SERVER
            else:
                ensure_plugin_dir_on_path()
                from ida_mcp.rpc import MCP_SERVER

            response = MCP_SERVER.registry.dispatch(msg)
            if response is not None:
                try:
                    self.ws.send(json.dumps(response))
                except Exception:
                    break
        self._alive = False

    def check_agents(self, timeout: float = 5) -> int:
        self._agent_count_event.clear()
        try:
            self.ws.send(json.dumps({"type": "check_agents"}))
        except Exception:
            return 0
        self._agent_count_event.wait(timeout=timeout)
        return self._agent_count

    def disconnect(self):
        self._alive = False
        try:
            self.ws.close()
        except Exception:
            pass
        self._thread.join(timeout=5)


class MCPPoolForm(idaapi.Form):
    """Form to configure pool connection."""

    def __init__(self, pool_url: str, session_name: str, auth_token: str):
        form_str = r"""STARTITEM 0
MCP Pool Connection

<Pool URL:{pool_url}>
<Session Name:{session_name}>
<Auth Token:{auth_token}>
"""
        super().__init__(
            form_str,
            {
                "pool_url": idaapi.Form.StringInput(value=pool_url),
                "session_name": idaapi.Form.StringInput(value=session_name),
                "auth_token": idaapi.Form.StringInput(value=auth_token),
            },
        )


class MCPPoolHandler(idaapi.action_handler_t):
    def __init__(self, plugin: "MCP"):
        idaapi.action_handler_t.__init__(self)
        self.plugin = plugin

    def activate(self, ctx):
        if self.plugin.pool_connector is not None:
            agents = 0
            try:
                agents = self.plugin.pool_connector.check_agents(timeout=3)
            except Exception:
                pass
            if agents > 0:
                answer = idaapi.ask_yn(
                    idaapi.ASKBTN_YES,
                    f"HIDECANCEL\n{agents} agent(s) are still using this session.\n"
                    f"Disconnect from pool?",
                )
                if answer != idaapi.ASKBTN_YES:
                    return 0
            self.plugin.pool_connector.disconnect()
            self.plugin.pool_connector = None
            print("[MCP] Disconnected from pool")
            return 1

        if TYPE_CHECKING:
            from .ida_mcp.http import config_json_get, config_json_set
        else:
            ensure_plugin_dir_on_path()
            from ida_mcp.http import config_json_get, config_json_set

        default_url = config_json_get("pool_url", "http://127.0.0.1:8750")
        default_name = ida_nalt.get_root_filename() or "ida-session"
        default_token = config_json_get("pool_auth_token", "")

        form = MCPPoolForm(default_url, default_name, default_token)
        form.Compile()
        ok = form.Execute()
        if ok != 1:
            form.Free()
            return 0

        pool_url = form.pool_url.value
        session_name = form.session_name.value
        auth_token = form.auth_token.value
        form.Free()

        config_json_set("pool_url", pool_url)
        config_json_set("pool_auth_token", auth_token)

        input_path = ida_nalt.get_input_file_path() or ""
        idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB) or ""

        try:
            connector = PoolConnector(
                pool_url, input_path, idb_path,
                session_name, auth_token,
            )
        except Exception as e:
            print(f"[MCP] Pool connection failed: {e}")
            return 0

        reg = connector.registration_response
        if not reg.get("success"):
            if reg.get("needs_confirm"):
                answer = idaapi.ask_yn(
                    idaapi.ASKBTN_YES,
                    f"HIDECANCEL\n{reg.get('message', 'Input path conflict')}.\n"
                    f"Register anyway?",
                )
                if answer != idaapi.ASKBTN_YES:
                    return 0
                try:
                    connector = PoolConnector(
                        pool_url, input_path, idb_path,
                        session_name, auth_token,
                        allow_duplicate_input=True,
                    )
                except Exception as e:
                    print(f"[MCP] Pool connection failed: {e}")
                    return 0
                reg = connector.registration_response
                if not reg.get("success"):
                    print(f"[MCP] Pool registration failed: {reg.get('error', 'unknown')}")
                    return 0
            else:
                print(f"[MCP] Pool registration failed: {reg.get('error', 'unknown')}")
                return 0

        self.plugin.pool_connector = connector
        sid = reg["session"]["session_id"]
        print(f"[MCP] Connected to pool at {pool_url} (session: {sid})")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class MCPLocalServerHandler(idaapi.action_handler_t):
    def __init__(self, plugin: "MCP"):
        idaapi.action_handler_t.__init__(self)
        self.plugin = plugin

    def activate(self, ctx):
        self.plugin.start_local_server()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class MCP(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "MCP Plugin"
    help = POOL_ACTION_LABEL
    wanted_name = POOL_ACTION_LABEL
    wanted_hotkey = "Ctrl-Alt-M"

    DEFAULT_HOST = "127.0.0.1"
    DEFAULT_PORT = 13337

    def init(self):
        hotkey = MCP.wanted_hotkey.replace("-", "+")
        if __import__("sys").platform == "darwin":
            hotkey = hotkey.replace("Alt", "Option")

        print(
            f"[MCP] Plugin loaded, use Edit -> Plugins -> MCP Pool ({hotkey}) to connect to a pool"
        )
        self.mcp: "ida_mcp.rpc.McpServer | None" = None
        self.host = self.DEFAULT_HOST
        self.port = self.DEFAULT_PORT
        self.pool_connector: PoolConnector | None = None
        self._pool_handler = MCPPoolHandler(self)

        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                CONFIG_ACTION_ID,
                CONFIG_ACTION_LABEL,
                MCPConfigHandler(self),
            )
        )
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                LOCAL_SERVER_ACTION_ID,
                LOCAL_SERVER_ACTION_LABEL,
                MCPLocalServerHandler(self),
            )
        )
        self._ui_hooks = MCPUIHooks()
        self._ui_hooks.hook()

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        return self._pool_handler.activate(None)

    def start_local_server(self):
        if self.mcp:
            self.mcp.stop()
            self.mcp = None

        # HACK: ensure fresh load of ida_mcp package
        unload_package("ida_mcp")
        if TYPE_CHECKING:
            from .ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler, init_caches
        else:
            ensure_plugin_dir_on_path()
            from ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler, init_caches

        try:
            init_caches()
        except Exception as e:
            print(f"[MCP] Cache init failed: {e}")

        port = self.port
        max_port = port + 100
        while port < max_port:
            try:
                MCP_SERVER.serve(
                    self.host, port, request_handler=IdaMcpHttpRequestHandler
                )
                print(f"  Config: http://{self.host}:{port}/config.html")
                self.mcp = MCP_SERVER
                return
            except OSError as e:
                if e.errno in (48, 98, 10048):  # Address already in use
                    port += 1
                else:
                    raise
        print(f"[MCP] Error: No available port in range {self.port}-{max_port - 1}")

    def term(self):
        if hasattr(self, "_ui_hooks"):
            self._ui_hooks.unhook()
        ida_kernwin.unregister_action(CONFIG_ACTION_ID)
        ida_kernwin.unregister_action(LOCAL_SERVER_ACTION_ID)
        if self.pool_connector:
            try:
                agents = self.pool_connector.check_agents(timeout=3)
                if agents > 0:
                    print(f"[MCP] Warning: {agents} agent(s) were using this session")
            except Exception:
                pass
            self.pool_connector.disconnect()
            self.pool_connector = None
        if self.mcp:
            self.mcp.stop()


def PLUGIN_ENTRY():
    return MCP()
