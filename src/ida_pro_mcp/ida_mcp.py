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
from typing import TYPE_CHECKING, Callable

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


MCP_MENU_ID = "mcp:menu"
CONNECT_POOL_ACTION_ID = "mcp:connect_pool"
CONNECT_POOL_ACTION_LABEL = "Connect to Pool"
DISCONNECT_POOL_ACTION_ID = "mcp:disconnect_pool"
DISCONNECT_POOL_ACTION_LABEL = "Disconnect from Pool"
CONFIG_ACTION_ID = "mcp:configure"
CONFIG_ACTION_LABEL = "Configuration"
RUN_LOCAL_SERVER_ACTION_ID = "mcp:run_local_server"
RUN_LOCAL_SERVER_ACTION_LABEL = "Run Local MCP Server"
SHUTDOWN_LOCAL_SERVER_ACTION_ID = "mcp:shutdown_local_server"
SHUTDOWN_LOCAL_SERVER_ACTION_LABEL = "Shutdown Local MCP Server"

MCP_ACTION_IDS = [
    CONNECT_POOL_ACTION_ID,
    DISCONNECT_POOL_ACTION_ID,
    CONFIG_ACTION_ID,
    RUN_LOCAL_SERVER_ACTION_ID,
    SHUTDOWN_LOCAL_SERVER_ACTION_ID,
]

POOL_WEBSOCKET_MAX_SIZE = 64 * 1024 * 1024


def action_state(enabled: bool):
    if enabled:
        return getattr(idaapi, "AST_ENABLE", ida_kernwin.AST_ENABLE)
    return getattr(idaapi, "AST_DISABLE", ida_kernwin.AST_DISABLE)


class MCPConfigForm(idaapi.Form):
    """Form to configure MCP server host and port."""

    def __init__(self, host: str, port: int, title: str = "MCP Configuration"):
        form_str = (
            "STARTITEM 0\n"
            f"{title}\n\n"
            "<Host:{host}>\n"
            "<Port:{port}>\n"
        )
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
        self.plugin._load_local_server_config()
        old_host = self.plugin.host
        old_port = self.plugin.port

        if not self.plugin._prompt_local_server_config("MCP Configuration"):
            return 0

        if self.plugin.host == old_host and self.plugin.port == old_port:
            print(f"[MCP] Configuration unchanged: {self.plugin.host}:{self.plugin.port}")
            return 1

        print(f"[MCP] Configuration updated: {self.plugin.host}:{self.plugin.port}")

        if self.plugin.mcp is not None:
            print("[MCP] Configuration will apply next time the local server starts")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class MCPUIHooks(ida_kernwin.UI_Hooks):
    """Defers menu attachment until the UI is fully ready."""

    def ready_to_run(self):
        ida_kernwin.create_menu(MCP_MENU_ID, "MCP")
        for action_id in MCP_ACTION_IDS:
            ida_kernwin.attach_action_to_menu("MCP/", action_id, idaapi.SETMENU_APP)
        self.unhook()

class PoolConnector:
    """Manages WebSocket connection from plugin to a pool server."""

    def __init__(self, pool_url: str, input_path: str, idb_path: str,
                 mcp_server: "ida_mcp.rpc.McpServer",
                 auth_token: str = "", allow_duplicate_input: bool = False,
                 on_disconnect: Callable[["PoolConnector"], None] | None = None):
        from websockets.sync.client import connect as ws_connect

        ws_url = pool_url.replace("http://", "ws://").replace("https://", "wss://")
        ws_url = ws_url.rstrip("/") + "/pool/ws"
        headers = {}
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"

        self.ws = ws_connect(
            ws_url,
            additional_headers=headers,
            proxy=None,
            max_size=POOL_WEBSOCKET_MAX_SIZE,
        )
        self.mcp_server = mcp_server
        self._alive = True
        self._disconnecting = False
        self._on_disconnect = on_disconnect
        self._agent_count = 0
        self._agent_count_event = threading.Event()

        self.ws.send(json.dumps({
            "type": "register",
            "input_path": input_path,
            "idb_path": idb_path,
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

    @property
    def alive(self) -> bool:
        return self._alive

    def _listen(self):
        try:
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

                response = self.mcp_server.registry.dispatch(msg)
                if response is not None:
                    try:
                        self.ws.send(json.dumps(response))
                    except Exception:
                        break
        finally:
            self._alive = False
            if not self._disconnecting and self._on_disconnect is not None:
                self._on_disconnect(self)

    def check_agents(self, timeout: float = 5) -> int:
        self._agent_count_event.clear()
        try:
            self.ws.send(json.dumps({"type": "check_agents"}))
        except Exception:
            return 0
        self._agent_count_event.wait(timeout=timeout)
        return self._agent_count

    def disconnect(self):
        self._disconnecting = True
        self._alive = False
        try:
            self.ws.close()
        except Exception:
            pass
        thread = getattr(self, "_thread", None)
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=5)


class MCPPoolForm(idaapi.Form):
    """Form to configure pool connection."""

    def __init__(self, pool_url: str, auth_token: str):
        form_str = r"""STARTITEM 0
MCP Pool Connection

<Pool URL:{pool_url}>
<Auth Token:{auth_token}>
"""
        super().__init__(
            form_str,
            {
                "pool_url": idaapi.Form.StringInput(value=pool_url),
                "auth_token": idaapi.Form.StringInput(value=auth_token),
            },
        )


class MCPConnectPoolHandler(idaapi.action_handler_t):
    def __init__(self, plugin: "MCP"):
        idaapi.action_handler_t.__init__(self)
        self.plugin = plugin

    def activate(self, ctx):
        return self.plugin.connect_pool()

    def update(self, ctx):
        return action_state(
            self.plugin.pool_connector is None and self.plugin.mcp is None
        )


class MCPDisconnectPoolHandler(idaapi.action_handler_t):
    def __init__(self, plugin: "MCP"):
        idaapi.action_handler_t.__init__(self)
        self.plugin = plugin

    def activate(self, ctx):
        return self.plugin.disconnect_pool(confirm=True)

    def update(self, ctx):
        return action_state(self.plugin.pool_connector is not None)


class MCPRunLocalServerHandler(idaapi.action_handler_t):
    def __init__(self, plugin: "MCP"):
        idaapi.action_handler_t.__init__(self)
        self.plugin = plugin

    def activate(self, ctx):
        return self.plugin.run_local_server()

    def update(self, ctx):
        return action_state(
            self.plugin.mcp is None and self.plugin.pool_connector is None
        )


class MCPShutdownLocalServerHandler(idaapi.action_handler_t):
    def __init__(self, plugin: "MCP"):
        idaapi.action_handler_t.__init__(self)
        self.plugin = plugin

    def activate(self, ctx):
        self.plugin.stop_local_server()
        return 1

    def update(self, ctx):
        return action_state(self.plugin.mcp is not None)


class MCP(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP | getattr(idaapi, "PLUGIN_HIDE", 0)
    comment = "MCP Plugin"
    help = "MCP"
    wanted_name = "MCP"
    wanted_hotkey = ""
    connect_hotkey = "Ctrl+Alt+M"

    DEFAULT_HOST = "127.0.0.1"
    DEFAULT_PORT = 13337

    def init(self):
        hotkey = self.connect_hotkey
        if __import__("sys").platform == "darwin":
            hotkey = hotkey.replace("Alt", "Option")

        print(
            f"[MCP] Plugin loaded, use MCP -> Connect to Pool ({hotkey}) to connect to a pool"
        )
        self.mcp: "ida_mcp.rpc.McpServer | None" = None
        self.host = self.DEFAULT_HOST
        self.port = self.DEFAULT_PORT
        self.pool_connector: PoolConnector | None = None
        self._connect_pool_handler = MCPConnectPoolHandler(self)
        self._disconnect_pool_handler = MCPDisconnectPoolHandler(self)
        self._config_handler = MCPConfigHandler(self)
        self._run_local_server_handler = MCPRunLocalServerHandler(self)
        self._shutdown_local_server_handler = MCPShutdownLocalServerHandler(self)

        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                CONNECT_POOL_ACTION_ID,
                CONNECT_POOL_ACTION_LABEL,
                self._connect_pool_handler,
                self.connect_hotkey,
            )
        )
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                DISCONNECT_POOL_ACTION_ID,
                DISCONNECT_POOL_ACTION_LABEL,
                self._disconnect_pool_handler,
            )
        )
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                CONFIG_ACTION_ID,
                CONFIG_ACTION_LABEL,
                self._config_handler,
            )
        )
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                RUN_LOCAL_SERVER_ACTION_ID,
                RUN_LOCAL_SERVER_ACTION_LABEL,
                self._run_local_server_handler,
            )
        )
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                SHUTDOWN_LOCAL_SERVER_ACTION_ID,
                SHUTDOWN_LOCAL_SERVER_ACTION_LABEL,
                self._shutdown_local_server_handler,
            )
        )
        self._ui_hooks = MCPUIHooks()
        self._ui_hooks.hook()
        self.update_menu_state()

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        return self.connect_pool()

    def update_menu_state(self):
        states = {
            CONNECT_POOL_ACTION_ID: self.pool_connector is None and self.mcp is None,
            DISCONNECT_POOL_ACTION_ID: self.pool_connector is not None,
            CONFIG_ACTION_ID: True,
            RUN_LOCAL_SERVER_ACTION_ID: self.mcp is None and self.pool_connector is None,
            SHUTDOWN_LOCAL_SERVER_ACTION_ID: self.mcp is not None,
        }
        for action_id, enabled in states.items():
            try:
                ida_kernwin.update_action_state(action_id, action_state(enabled))
            except Exception:
                pass

    def _load_local_server_config(self):
        try:
            ensure_plugin_dir_on_path()
            from ida_mcp.config import config_json_get
            self.host = config_json_get("local_server_host", self.host)
            self.port = int(config_json_get("local_server_port", self.port))
        except Exception:
            pass

    def _save_local_server_config(self):
        try:
            ensure_plugin_dir_on_path()
            from ida_mcp.config import config_json_set
            config_json_set("local_server_host", self.host)
            config_json_set("local_server_port", self.port)
        except Exception as e:
            print(f"[MCP] Failed to save local server configuration: {e}")

    def _prompt_local_server_config(self, title: str) -> bool:
        self._load_local_server_config()
        form = MCPConfigForm(self.host, self.port, title)
        form.Compile()
        ok = form.Execute()
        if ok != 1:
            form.Free()
            return False

        host = form.host.value
        port = form.port.value
        form.Free()

        if port < 1 or port > 65535:
            print(f"[MCP] Invalid port: {port}")
            return False

        self.host = host
        self.port = port
        self._save_local_server_config()
        return True

    def _execute_ui(self, callback):
        try:
            return ida_kernwin.execute_sync(
                callback,
                getattr(ida_kernwin, "MFF_FAST", 0),
            )
        except Exception:
            return callback()

    def _handle_pool_disconnected(self, connector: PoolConnector):
        def cleanup():
            if self.pool_connector is not connector:
                return 0
            self.pool_connector = None
            print("[MCP] Pool server disconnected")
            self.update_menu_state()
            return 1

        self._execute_ui(cleanup)

    def connect_pool(self):
        if self.pool_connector is not None:
            print("[MCP] Already connected to pool")
            return 0
        if self.mcp is not None:
            print("[MCP] Stop the local MCP server before connecting to a pool")
            return 0

        if TYPE_CHECKING:
            from .ida_mcp.config import config_json_get, config_json_set
        else:
            ensure_plugin_dir_on_path()
            from ida_mcp.config import config_json_get, config_json_set

        default_url = config_json_get("pool_url", "http://127.0.0.1:8750")
        default_token = config_json_get("pool_auth_token", "")

        form = MCPPoolForm(default_url, default_token)
        form.Compile()
        ok = form.Execute()
        if ok != 1:
            form.Free()
            return 0

        pool_url = form.pool_url.value
        auth_token = form.auth_token.value
        form.Free()

        config_json_set("pool_url", pool_url)
        config_json_set("pool_auth_token", auth_token)

        input_path = ida_nalt.get_input_file_path() or ""
        idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB) or ""

        # Pool mode must use a fresh registry. A previous local-server config
        # page may have filtered MCP_SERVER.tools in this GUI process.
        unload_package("ida_mcp")
        if TYPE_CHECKING:
            from .ida_mcp import MCP_SERVER
        else:
            ensure_plugin_dir_on_path()
            from ida_mcp import MCP_SERVER

        try:
            connector = PoolConnector(
                pool_url, input_path, idb_path,
                MCP_SERVER,
                auth_token,
                on_disconnect=self._handle_pool_disconnected,
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
                        MCP_SERVER,
                        auth_token,
                        allow_duplicate_input=True,
                        on_disconnect=self._handle_pool_disconnected,
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

        self.pool_connector = connector
        if not connector.alive:
            self._handle_pool_disconnected(connector)
            return 0
        sid = reg["session"]["session_id"]
        print(f"[MCP] Connected to pool at {pool_url} (session: {sid})")
        self.update_menu_state()
        return 1

    def disconnect_pool(self, *, confirm: bool):
        if self.pool_connector is None:
            print("[MCP] Not connected to pool")
            return 0

        agents = 0
        try:
            agents = self.pool_connector.check_agents(timeout=3)
        except Exception:
            pass
        if confirm and agents > 0:
            answer = idaapi.ask_yn(
                idaapi.ASKBTN_YES,
                f"HIDECANCEL\n{agents} agent(s) are still using this session.\n"
                f"Disconnect from pool?",
            )
            if answer != idaapi.ASKBTN_YES:
                return 0
        self.pool_connector.disconnect()
        self.pool_connector = None
        print("[MCP] Disconnected from pool")
        self.update_menu_state()
        return 1

    def run_local_server(self):
        if self.pool_connector is not None:
            print("[MCP] Disconnect from pool before running the local MCP server")
            return 0
        if self.mcp is not None:
            print("[MCP] Local MCP server is already running")
            return 0
        if not self._prompt_local_server_config("Run Local MCP Server"):
            return 0
        return self.start_local_server()

    def start_local_server(self):
        if self.pool_connector is not None:
            print("[MCP] Disconnect from pool before running the local MCP server")
            return 0
        if self.mcp:
            print("[MCP] Local MCP server is already running")
            return 0

        # HACK: ensure fresh load of ida_mcp package
        unload_package("ida_mcp")
        if TYPE_CHECKING:
            from .ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler, init_caches
            from .ida_mcp.rpc import set_download_base_url
        else:
            ensure_plugin_dir_on_path()
            from ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler, init_caches
            from ida_mcp.rpc import set_download_base_url

        try:
            init_caches()
        except Exception as e:
            print(f"[MCP] Cache init failed: {e}")

        try:
            set_download_base_url(
                os.environ.get("IDA_MCP_URL")
                or f"http://{self.host}:{self.port}"
            )
            MCP_SERVER.serve(
                self.host, self.port, request_handler=IdaMcpHttpRequestHandler
            )
            self.mcp = MCP_SERVER
            self.update_menu_state()
            return 1
        except OSError as e:
            if e.errno in (48, 98, 10048):  # Address already in use
                print(f"[MCP] Error: {self.host}:{self.port} is already in use")
                return 0
            raise

    def stop_local_server(self):
        if self.mcp is None:
            print("[MCP] Local MCP server is not running")
            return 0
        self.mcp.stop()
        self.mcp = None
        print("[MCP] Local MCP server stopped")
        self.update_menu_state()
        return 1

    def term(self):
        if hasattr(self, "_ui_hooks"):
            self._ui_hooks.unhook()
        for action_id in MCP_ACTION_IDS:
            try:
                ida_kernwin.detach_action_from_menu("MCP/", action_id)
            except Exception:
                pass
            ida_kernwin.unregister_action(action_id)
        try:
            ida_kernwin.delete_menu(MCP_MENU_ID)
        except Exception:
            pass
        if self.pool_connector is not None:
            self.disconnect_pool(confirm=False)
        if self.mcp is not None:
            self.stop_local_server()


def PLUGIN_ENTRY():
    return MCP()
