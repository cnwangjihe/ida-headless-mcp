"""Event-driven local administration interface for the idalib pool."""

from __future__ import annotations

import logging
import shlex
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from rich.text import Text
from textual import events, work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, RichLog, Tree

from ida_pro_mcp.admin_events import AdminEvent, AdminEventBus


logger = logging.getLogger("ida_mcp.tui")

TUI_COMMANDS = (
    "help",
    "show",
    "save",
    "close",
    "disconnect",
    "unregister",
    "clear",
    "quit",
)


class BufferedLogHandler(logging.Handler):
    """A bounded logging handler which may be drained from the UI thread."""

    def __init__(self, capacity: int = 4096) -> None:
        super().__init__()
        if capacity <= 0:
            raise ValueError("Log buffer capacity must be positive")
        self._records: deque[str] = deque(maxlen=capacity)
        self._buffer_lock = threading.Lock()
        self._dropped_since_drain = 0

    def emit(self, record: logging.LogRecord) -> None:
        try:
            message = self.format(record)
        except Exception:
            self.handleError(record)
            return
        with self._buffer_lock:
            if len(self._records) == self._records.maxlen:
                self._dropped_since_drain += 1
            self._records.append(message)

    def drain(self) -> tuple[list[str], int]:
        with self._buffer_lock:
            records = list(self._records)
            self._records.clear()
            dropped = self._dropped_since_drain
            self._dropped_since_drain = 0
        return records, dropped


@dataclass
class DashboardModel:
    """Incremental UI-owned state; core managers remain the authority."""

    transports: dict[str, dict[str, Any]] = field(default_factory=dict)
    contexts: dict[str, dict[str, Any]] = field(default_factory=dict)
    databases: dict[str, dict[str, Any]] = field(default_factory=dict)
    openings: dict[str, dict[str, Any]] = field(default_factory=dict)
    _revisions: dict[tuple[str, str], int] = field(default_factory=dict)

    def apply(self, event: AdminEvent) -> bool:
        if event.source == "mcp":
            entity_type = "transport"
        elif event.kind in {"IdbOpenStarted", "IdbOpenFinished"}:
            entity_type = "opening"
        elif event.kind == "ContextMappingChanged":
            entity_type = "context"
        else:
            entity_type = "database"

        revision_key = (entity_type, event.entity_id)
        if event.revision <= self._revisions.get(revision_key, -1):
            return False
        self._revisions[revision_key] = event.revision

        if entity_type == "transport":
            if event.kind == "TransportClosed":
                self.transports.pop(event.entity_id, None)
                context = self.contexts.get(event.entity_id)
                if context is not None and not self._context_has_relations(context):
                    self.contexts.pop(event.entity_id, None)
            else:
                self.transports[event.entity_id] = dict(event.payload)
            return True

        if entity_type == "opening":
            if event.kind == "IdbOpenFinished":
                self.openings.pop(event.entity_id, None)
            else:
                self.openings[event.entity_id] = dict(event.payload)
            return True

        if entity_type == "context":
            context = dict(event.payload)
            if (
                event.entity_id not in self.transports
                and not self._context_has_relations(context)
            ):
                self.contexts.pop(event.entity_id, None)
            else:
                self.contexts[event.entity_id] = context
            return True

        if event.kind in {"IdbClosed", "ExternalIdbUnregistered"}:
            self.databases.pop(event.entity_id, None)
        else:
            self.databases[event.entity_id] = dict(event.payload)
        return True

    @staticmethod
    def _context_has_relations(context: dict[str, Any]) -> bool:
        return bool(
            context.get("bound_session_id") or context.get("held_session_ids")
        )

    def agent_ids(self) -> set[str]:
        context_ids = set(self.transports) | {
            context_id
            for context_id, context in self.contexts.items()
            if self._context_has_relations(context)
        }
        context_ids.update(
            context_id
            for opening in self.openings.values()
            if (context_id := opening.get("context_id"))
        )
        return context_ids


class StableAliases:
    def __init__(self) -> None:
        self._agents: dict[str, str] = {}
        self._databases: dict[str, str] = {}

    def agent(self, context_id: str) -> str:
        alias = self._agents.get(context_id)
        if alias is None:
            alias = f"A{len(self._agents) + 1:02d}"
            self._agents[context_id] = alias
        return alias

    def database(self, session_id: str) -> str:
        alias = self._databases.get(session_id)
        if alias is None:
            alias = f"D{len(self._databases) + 1:02d}"
            self._databases[session_id] = alias
        return alias

    def agent_items(self) -> tuple[tuple[str, str], ...]:
        return tuple(self._agents.items())

    def database_items(self) -> tuple[tuple[str, str], ...]:
        return tuple(self._databases.items())

    def resolve_agent(self, token: str, available: set[str]) -> str:
        return self._resolve(token, available, self._agents, "agent")

    def resolve_database(self, token: str, available: set[str]) -> str:
        return self._resolve(token, available, self._databases, "database")

    def resolve_any(
        self,
        token: str,
        agents: set[str],
        databases: set[str],
    ) -> tuple[str, str]:
        normalized = token.casefold()
        if normalized.startswith("a"):
            return "agent", self.resolve_agent(token, agents)
        if normalized.startswith("d"):
            return "database", self.resolve_database(token, databases)

        matches = [
            ("agent", entity_id)
            for entity_id in agents
            if entity_id == token or entity_id.startswith(token)
        ]
        matches.extend(
            ("database", entity_id)
            for entity_id in databases
            if entity_id == token or entity_id.startswith(token)
        )
        if len(matches) == 1:
            return matches[0]
        if not matches:
            raise ValueError(f"Target not found: {token}")
        raise ValueError(f"Ambiguous target prefix: {token}")

    @staticmethod
    def _resolve(
        token: str,
        available: set[str],
        aliases: dict[str, str],
        kind: str,
    ) -> str:
        normalized = token.casefold()
        alias_matches = [
            entity_id
            for entity_id, alias in aliases.items()
            if alias.casefold() == normalized and entity_id in available
        ]
        if len(alias_matches) == 1:
            return alias_matches[0]
        if token in available:
            return token
        prefix_matches = sorted(
            entity_id for entity_id in available if entity_id.startswith(token)
        )
        if len(prefix_matches) == 1:
            return prefix_matches[0]
        if not prefix_matches:
            raise ValueError(f"{kind.title()} not found: {token}")
        raise ValueError(f"Ambiguous {kind} prefix: {token}")


def format_duration(seconds: float) -> str:
    minutes = max(0, int(seconds // 60))
    if minutes < 1:
        return "<1m"
    if minutes < 60:
        return f"{minutes}m"
    hours, remaining_minutes = divmod(minutes, 60)
    if hours < 24:
        return f"{hours}h{remaining_minutes}m"
    days, remaining_hours = divmod(hours, 24)
    return f"{days}d{remaining_hours}h"


TreeTarget = tuple[str, str]


class SessionTree(Tree[TreeTarget], can_focus=False):
    """Mouse-operable tree which never takes focus from the console."""


class SessionLog(RichLog, can_focus=False):
    """Scrollable log which never takes focus from the console."""


class ConfirmActionScreen(ModalScreen[bool]):
    CSS = """
    ConfirmActionScreen {
        align: center middle;
    }

    #confirm-dialog {
        width: 72;
        max-width: 90%;
        height: auto;
        padding: 1 2;
        border: round $warning;
        background: $surface;
    }

    #confirm-buttons {
        width: 100%;
        height: auto;
        align-horizontal: right;
        margin-top: 1;
    }
    """

    BINDINGS = [
        ("tab", "next_option", "Next option"),
        ("shift+tab", "previous_option", "Previous option"),
        ("left,up", "focus_cancel", "Cancel"),
        ("right,down", "focus_confirm", "Confirm"),
        ("enter,space", "activate_option", "Select"),
        ("y", "confirm", "Confirm"),
        ("n,escape", "cancel", "Cancel"),
    ]

    def __init__(self, message: str) -> None:
        super().__init__()
        self.message = message

    def compose(self) -> ComposeResult:
        with Vertical(id="confirm-dialog"):
            yield Label(self.message)
            with Horizontal(id="confirm-buttons"):
                yield Button("Cancel", id="cancel", variant="default")
                yield Button("Confirm", id="confirm", variant="error")

    def on_mount(self) -> None:
        self.query_one("#cancel", Button).focus()

    def on_button_pressed(self, message: Button.Pressed) -> None:
        self.dismiss(message.button.id == "confirm")

    def action_cancel(self) -> None:
        self.dismiss(False)

    def action_confirm(self) -> None:
        self.dismiss(True)

    def action_focus_cancel(self) -> None:
        self.query_one("#cancel", Button).focus()

    def action_focus_confirm(self) -> None:
        self.query_one("#confirm", Button).focus()

    def action_next_option(self) -> None:
        if getattr(self.focused, "id", None) == "cancel":
            self.action_focus_confirm()
        else:
            self.action_focus_cancel()

    def action_previous_option(self) -> None:
        if getattr(self.focused, "id", None) == "confirm":
            self.action_focus_cancel()
        else:
            self.action_focus_confirm()

    def action_activate_option(self) -> None:
        self.dismiss(getattr(self.focused, "id", None) == "confirm")


class PoolTuiApp(App[None]):
    """Read-only session relationship tree and unified main-process log pane."""

    CSS = """
    Screen {
        layout: vertical;
    }

    #session-tree {
        height: 45%;
        min-height: 10;
        border: round $accent;
    }

    #main-log {
        height: 1fr;
        border: round $primary;
    }

    #command-input {
        height: 1;
        min-height: 1;
        border: none;
        padding: 0 1;
        background: $panel;
    }
    """

    def __init__(
        self,
        event_bus: AdminEventBus,
        log_handler: BufferedLogHandler,
        *,
        mcp_server: Any | None = None,
        pool_manager: Any | None = None,
        startup_callback: Callable[[], None] | None = None,
    ) -> None:
        super().__init__()
        self.event_bus = event_bus
        self.log_handler = log_handler
        self.mcp_server = mcp_server
        self.pool_manager = pool_manager
        self.startup_callback = startup_callback
        self.model = DashboardModel()
        self.aliases = StableAliases()
        self.runtime_state = "STARTING"
        self.runtime_detail = ""
        self._collapsed_agents: set[str] = set()
        self._event_bridge_started = False
        self._command_history: list[str] = []
        self._history_index = 0
        self._busy_targets: set[TreeTarget] = set()
        self._completion_candidates: tuple[str, ...] = ()
        self._completion_index = -1
        self._completion_head = ""
        self._completion_tail = ""
        self._completion_value: str | None = None
        self._completion_cursor = 0

    def compose(self) -> ComposeResult:
        yield SessionTree("Sessions", id="session-tree")
        yield SessionLog(
            max_lines=2000,
            wrap=False,
            markup=False,
            auto_scroll=True,
            id="main-log",
        )
        yield Input(
            placeholder="help | show A01 | save D01 | close D01",
            compact=True,
            id="command-input",
        )

    def on_mount(self) -> None:
        tree = self.query_one("#session-tree", Tree)
        tree.root.expand()
        self._rebuild_tree()
        self.event_bus.start(self._deliver_admin_event)
        self._event_bridge_started = True
        self.set_interval(60, self._refresh_durations, name="duration-refresh")
        self.set_interval(0.1, self._drain_logs, name="log-drain")
        self.query_one("#command-input", Input).focus()
        if self.startup_callback is not None:
            self.startup_callback()

    def on_unmount(self) -> None:
        if self._event_bridge_started:
            self.event_bus.stop(wait=False)
            self._event_bridge_started = False

    def _deliver_admin_event(self, event: AdminEvent) -> None:
        self.call_from_thread(self.apply_admin_event, event)

    def apply_admin_event(self, event: AdminEvent) -> None:
        if not self.model.apply(event):
            return
        if event.source == "mcp" or event.kind == "ContextMappingChanged":
            self.aliases.agent(event.entity_id)
        if event.source == "pool" and event.kind not in {
            "ContextMappingChanged",
            "IdbOpenStarted",
            "IdbOpenFinished",
        }:
            self.aliases.database(event.entity_id)
        self._rebuild_tree()

    def set_runtime_state(self, state: str, detail: str = "") -> None:
        self.runtime_state = state
        self.runtime_detail = detail
        if self.is_mounted:
            self._rebuild_tree()

    def _refresh_durations(self) -> None:
        self._rebuild_tree()

    def _drain_logs(self) -> None:
        records, dropped = self.log_handler.drain()
        if not records and not dropped:
            return
        log = self.query_one("#main-log", RichLog)
        if dropped:
            log.write(f"[TUI] {dropped} buffered log record(s) overwritten")
        for record in records:
            log.write(record)

    def on_input_submitted(self, message: Input.Submitted) -> None:
        self._reset_completion()
        command_line = message.value.strip()
        message.input.value = ""
        if not command_line:
            return
        if not self._command_history or self._command_history[-1] != command_line:
            self._command_history.append(command_line)
            del self._command_history[:-100]
        self._history_index = len(self._command_history)
        self.execute_command(command_line)

    def on_key(self, event: events.Key) -> None:
        command_input = self.query_one("#command-input", Input)
        if (
            self.screen is not command_input.screen
            or self.screen.focused is not command_input
        ):
            return
        if event.key in {"pageup", "pagedown"}:
            event.stop()
            event.prevent_default()
            log = self.query_one("#main-log", RichLog)
            if event.key == "pageup":
                log.scroll_page_up(animate=False)
            else:
                log.scroll_page_down(animate=False)
            return
        if event.key == "tab":
            event.stop()
            event.prevent_default()
            self._complete_command(command_input)
            return
        self._reset_completion()
        if event.key not in {"up", "down"}:
            return
        if not self._command_history:
            return
        event.stop()
        event.prevent_default()
        if event.key == "up":
            self._history_index = max(0, self._history_index - 1)
            command_input.value = self._command_history[self._history_index]
        else:
            self._history_index = min(
                len(self._command_history), self._history_index + 1
            )
            command_input.value = (
                self._command_history[self._history_index]
                if self._history_index < len(self._command_history)
                else ""
            )
        command_input.cursor_position = len(command_input.value)

    def _complete_command(self, command_input: Input) -> None:
        if (
            self._completion_candidates
            and command_input.value == self._completion_value
            and command_input.cursor_position == self._completion_cursor
        ):
            self._completion_index = (
                self._completion_index + 1
            ) % len(self._completion_candidates)
            self._apply_completion_candidate(command_input)
            return

        self._reset_completion()
        value = command_input.value
        cursor = command_input.cursor_position
        token_start = cursor
        while token_start > 0 and not value[token_start - 1].isspace():
            token_start -= 1
        token = value[token_start:cursor]
        preceding = value[:token_start].split()
        candidates = tuple(
            candidate
            for candidate in self._completion_options(preceding)
            if candidate.casefold().startswith(token.casefold())
        )
        if not candidates:
            return

        head = value[:token_start]
        tail = value[cursor:]
        if len(candidates) == 1:
            completed = candidates[0]
            if not tail and (not completed or not completed[-1].isspace()):
                completed += " "
            command_input.value = f"{head}{completed}{tail}"
            command_input.cursor_position = len(head) + len(completed)
            return

        folded = [candidate.casefold() for candidate in candidates]
        common_length = 0
        for characters in zip(*folded):
            if len(set(characters)) != 1:
                break
            common_length += 1
        if common_length > len(token):
            common_prefix = candidates[0][:common_length]
            command_input.value = f"{head}{common_prefix}{tail}"
            command_input.cursor_position = len(head) + len(common_prefix)
            return

        self._completion_candidates = candidates
        self._completion_index = 0
        self._completion_head = head
        self._completion_tail = tail
        self._apply_completion_candidate(command_input)

    def _completion_options(self, preceding: list[str]) -> tuple[str, ...]:
        if not preceding:
            return TUI_COMMANDS
        command = preceding[0].casefold()
        if len(preceding) > 1:
            return ()
        if command == "help":
            return TUI_COMMANDS

        agent_ids = self.model.agent_ids()
        agents = tuple(
            sorted(
                alias
                for entity_id, alias in self.aliases.agent_items()
                if entity_id in agent_ids
            )
        )
        databases = tuple(
            sorted(
                (alias, self.model.databases[entity_id])
                for entity_id, alias in self.aliases.database_items()
                if entity_id in self.model.databases
            )
        )
        if command == "disconnect":
            return agents
        if command == "show":
            return agents + tuple(alias for alias, _database in databases)
        if command == "save":
            return tuple(alias for alias, _database in databases)
        if command == "close":
            return tuple(
                alias
                for alias, database in databases
                if not database.get("is_external")
            )
        if command == "unregister":
            return tuple(
                alias
                for alias, database in databases
                if database.get("is_external")
            )
        return ()

    def _apply_completion_candidate(self, command_input: Input) -> None:
        candidate = self._completion_candidates[self._completion_index]
        self._completion_value = (
            f"{self._completion_head}{candidate}{self._completion_tail}"
        )
        self._completion_cursor = len(self._completion_head) + len(candidate)
        command_input.value = self._completion_value
        command_input.cursor_position = self._completion_cursor

    def _reset_completion(self) -> None:
        self._completion_candidates = ()
        self._completion_index = -1
        self._completion_head = ""
        self._completion_tail = ""
        self._completion_value = None
        self._completion_cursor = 0

    def execute_command(self, command_line: str) -> None:
        try:
            parts = shlex.split(command_line)
        except ValueError as e:
            self._console_error(f"Invalid command: {e}")
            return
        if not parts:
            return
        command = parts[0].casefold()
        arguments = parts[1:]

        if command == "help":
            self._show_help(arguments[0] if arguments else None)
            return
        if command == "clear":
            if arguments:
                self._console_error("Usage: clear")
                return
            self.query_one("#main-log", RichLog).clear()
            return
        if command == "quit":
            if arguments:
                self._console_error("Usage: quit")
                return
            self.exit()
            return
        if command == "show":
            if len(arguments) != 1:
                self._console_error("Usage: show <agent-or-db>")
                return
            self._show_target(arguments[0])
            return
        if command not in {"save", "close", "disconnect", "unregister"}:
            self._console_error(f"Unknown command: {command}; use 'help'")
            return
        if len(arguments) != 1:
            self._console_error(f"Usage: {command} <target>")
            return
        if self.mcp_server is None or self.pool_manager is None:
            self._console_error("Administration controls are not connected")
            return

        try:
            if command == "disconnect":
                entity_id = self.aliases.resolve_agent(
                    arguments[0], self.model.agent_ids()
                )
                target = ("agent", entity_id)
            else:
                entity_id = self.aliases.resolve_database(
                    arguments[0], set(self.model.databases)
                )
                target = ("database", entity_id)
        except ValueError as e:
            self._console_error(str(e))
            return

        if target in self._busy_targets:
            self._console_error(f"Target is already busy: {arguments[0]}")
            return
        if target[0] == "database":
            is_external = bool(
                self.model.databases[target[1]].get("is_external")
            )
            if command == "close" and is_external:
                self._console_error(
                    "External GUI databases cannot be force-closed; "
                    "use 'unregister'"
                )
                return
            if command == "unregister" and not is_external:
                self._console_error(
                    "Local databases cannot be unregistered; use 'close'"
                )
                return
        if command == "save":
            self._start_admin_action(command, target)
            return

        confirmation = self._confirmation_message(command, target)
        self.push_screen(
            ConfirmActionScreen(confirmation),
            callback=lambda confirmed: (
                self._start_admin_action(command, target) if confirmed else None
            ),
        )

    def _show_help(self, command: str | None) -> None:
        help_text = {
            "show": "show <agent-or-db>  Display full IDs, mappings and paths",
            "save": "save <db>           Save without changing leases",
            "close": "close <db>          Force-close a local IDB after confirmation",
            "disconnect": (
                "disconnect <agent>  Reject new requests and release all leases"
            ),
            "unregister": (
                "unregister <db>     Detach an external GUI IDB from the pool"
            ),
            "clear": "clear               Clear the visible log",
            "quit": "quit                Stop the TUI",
        }
        if command is not None:
            text = help_text.get(command.casefold())
            if text is None:
                self._console_error(f"Unknown command: {command}")
            else:
                logger.info(text)
            return
        logger.info("Commands:\n%s", "\n".join(help_text.values()))

    def _show_target(self, token: str) -> None:
        try:
            kind, entity_id = self.aliases.resolve_any(
                token,
                self.model.agent_ids(),
                set(self.model.databases),
            )
        except ValueError as e:
            self._console_error(str(e))
            return
        if kind == "agent":
            transport = self.model.transports.get(entity_id, {})
            relation = self.model.contexts.get(entity_id, {})
            now = time.monotonic()
            openings = sorted(
                (
                    operation_id,
                    opening,
                )
                for operation_id, opening in self.model.openings.items()
                if opening.get("context_id") == entity_id
            )
            opening_details = "\n             ".join(
                f"{operation_id} {opening.get('input_path') or '-'} "
                f"(age {format_duration(now - float(opening.get('started_at', now)))})"
                for operation_id, opening in openings
            )
            logger.info(
                "Agent %s\n  context: %s\n  client: %s %s\n  peer: %s\n"
                "  state: %s\n  active requests: %s\n  opening: %s\n"
                "  bound: %s\n  holds: %s",
                self.aliases.agent(entity_id),
                entity_id,
                transport.get("client_name") or "unknown",
                transport.get("client_version") or "",
                transport.get("peer") or "-",
                transport.get("state") or "ORPHAN",
                transport.get("active_requests", 0),
                opening_details or "-",
                relation.get("bound_session_id") or "-",
                ", ".join(relation.get("held_session_ids", [])) or "-",
            )
            return

        database = self.model.databases[entity_id]
        holders = sorted(
            context_id
            for context_id, relation in self.model.contexts.items()
            if entity_id in relation.get("held_session_ids", [])
        )
        logger.info(
            "Database %s\n  session: %s\n  input: %s\n  idb: %s\n"
            "  type: %s\n  state: %s\n  refcount: %s\n  holders: %s\n"
            "  instance: %s\n  pid: %s\n  backend log: %s",
            self.aliases.database(entity_id),
            entity_id,
            database.get("input_path") or "-",
            database.get("idb_path") or "-",
            "GUI" if database.get("is_external") else "LOCAL",
            database.get("state") or "UNKNOWN",
            database.get("refcount", 0),
            ", ".join(holders) or "-",
            database.get("instance_index", "-"),
            database.get("pid") or "-",
            database.get("log_path") or "-",
        )

    def _confirmation_message(self, command: str, target: TreeTarget) -> str:
        kind, entity_id = target
        if kind == "agent":
            relation = self.model.contexts.get(entity_id, {})
            transport = self.model.transports.get(entity_id, {})
            held = relation.get("held_session_ids", [])
            return (
                f"Disconnect {self.aliases.agent(entity_id)}?\n\n"
                f"Active requests: {transport.get('active_requests', 0)}\n"
                f"Held IDBs: {', '.join(held) or '-'}\n\n"
                "New requests will be rejected immediately; active requests drain "
                "before leases are released."
            )

        database = self.model.databases.get(entity_id, {})
        alias = self.aliases.database(entity_id)
        holders = sorted(
            self.aliases.agent(context_id)
            for context_id, relation in self.model.contexts.items()
            if entity_id in relation.get("held_session_ids", [])
        )
        if command == "close":
            return (
                f"Force-close {alias}?\n\n"
                f"Refcount: {database.get('refcount', 0)}\n"
                f"Agents: {', '.join(holders) or '-'}\n\n"
                "All mappings will be revoked. This is only allowed for local IDBs."
            )
        return (
            f"Unregister external database {alias}?\n\n"
            f"Agents: {', '.join(holders) or '-'}\n\n"
            "The pool connection will close; the IDB remains open in IDA GUI."
        )

    def _start_admin_action(self, command: str, target: TreeTarget) -> None:
        if target in self._busy_targets:
            return
        self._busy_targets.add(target)
        logger.info(
            "Administration action started: command=%s target=%s",
            command,
            target[1],
        )
        self._run_admin_action(command, target)

    @work(thread=True, exit_on_error=False, group="admin-actions")
    def _run_admin_action(self, command: str, target: TreeTarget) -> None:
        result = self._perform_admin_action(command, target)
        self.call_from_thread(
            self._complete_admin_action,
            command,
            target,
            result,
        )

    def _perform_admin_action(
        self,
        command: str,
        target: TreeTarget,
    ) -> dict[str, Any]:
        kind, entity_id = target
        try:
            if command == "save":
                result = self.pool_manager.save_session(entity_id)
            elif command == "close":
                result = self.pool_manager.close_session(entity_id)
            elif command == "unregister":
                result = self.pool_manager.unregister_external(entity_id)
            elif command == "disconnect":
                result = self.mcp_server.disconnect_transport_session(entity_id)
                if (
                    not result.get("success")
                    and "not found" in str(result.get("error", "")).casefold()
                ):
                    release = self.pool_manager.release_context(entity_id)
                    result = {
                        **release,
                        "success": release.get("success", False),
                        "orphan_context_cleaned": True,
                    }
            else:
                result = {"success": False, "error": f"Unknown action: {command}"}
        except Exception as e:
            result = {"success": False, "error": str(e)}
        return result

    def _complete_admin_action(
        self,
        command: str,
        target: TreeTarget,
        result: dict[str, Any],
    ) -> None:
        self._busy_targets.discard(target)
        if result.get("success"):
            logger.info(
                "Administration action completed: command=%s target=%s result=%s",
                command,
                target[1],
                result,
            )
        else:
            self._console_error(
                f"{command} failed for {target[1]}: "
                f"{result.get('error') or result}"
            )

    @staticmethod
    def _console_error(message: str) -> None:
        logger.error(message)

    def _remember_tree_state(self, tree: Tree[TreeTarget]) -> TreeTarget | None:
        selected = tree.cursor_node.data if tree.cursor_node is not None else None
        for node in tree.root.children:
            data = node.data
            if data is None or data[0] != "agent":
                continue
            if node.is_expanded:
                self._collapsed_agents.discard(data[1])
            else:
                self._collapsed_agents.add(data[1])
        return selected

    def _rebuild_tree(self) -> None:
        tree = self.query_one("#session-tree", Tree)
        selected = self._remember_tree_state(tree)
        tree.clear()

        agent_ids = self.model.agent_ids()
        root_label = Text()
        root_label.append("Sessions", style="bold")
        root_label.append(
            f" · {self.runtime_state} · MCP {len(agent_ids)}"
            f" · IDB {len(self.model.databases)}"
        )
        if self.model.openings:
            root_label.append(f" · OPENING {len(self.model.openings)}", style="yellow")
        if self.runtime_detail:
            root_label.append(f" · {self.runtime_detail}")
        tree.root.set_label(root_label)
        tree.root.expand()

        nodes_by_target: dict[TreeTarget, Any] = {}
        referenced_databases: set[str] = set()
        referenced_openings: set[str] = set()
        now = time.monotonic()

        ordered_agents = sorted(agent_ids, key=self.aliases.agent)
        for context_id in ordered_agents:
            alias = self.aliases.agent(context_id)
            transport = self.model.transports.get(context_id)
            relation = self.model.contexts.get(context_id, {})
            node = tree.root.add(
                self._agent_label(alias, transport, now),
                data=("agent", context_id),
                expand=context_id not in self._collapsed_agents,
            )
            nodes_by_target[("agent", context_id)] = node

            held = set(relation.get("held_session_ids", []))
            bound = relation.get("bound_session_id")
            session_ids = held | ({bound} if bound else set())
            referenced_databases.update(session_ids)
            openings = sorted(
                (
                    operation_id,
                    opening,
                )
                for operation_id, opening in self.model.openings.items()
                if opening.get("context_id") == context_id
            )
            for operation_id, opening in openings:
                referenced_openings.add(operation_id)
                child = node.add_leaf(
                    self._opening_label(opening, now),
                    data=("opening", operation_id),
                )
                nodes_by_target[("opening", operation_id)] = child
            if not session_ids and not openings:
                node.add_leaf(Text("no IDB sessions", style="dim"))
                continue
            for session_id in sorted(session_ids, key=self.aliases.database):
                child = node.add_leaf(
                    self._database_label(
                        session_id,
                        self.model.databases.get(session_id),
                        bound=session_id == bound,
                    ),
                    data=("database", session_id),
                )
                nodes_by_target.setdefault(("database", session_id), child)

        unattached_openings = sorted(
            set(self.model.openings) - referenced_openings
        )
        if unattached_openings:
            branch = tree.root.add(
                f"Unattached opening operations ({len(unattached_openings)})",
                data=("group", "unattached-openings"),
                expand=True,
            )
            for operation_id in unattached_openings:
                child = branch.add_leaf(
                    self._opening_label(self.model.openings[operation_id], now),
                    data=("opening", operation_id),
                )
                nodes_by_target[("opening", operation_id)] = child

        unattached = sorted(
            set(self.model.databases) - referenced_databases,
            key=self.aliases.database,
        )
        if unattached:
            branch = tree.root.add(
                f"Unattached / Closing IDBs ({len(unattached)})",
                data=("group", "unattached"),
                expand=True,
            )
            for session_id in unattached:
                child = branch.add_leaf(
                    self._database_label(
                        session_id,
                        self.model.databases[session_id],
                        bound=False,
                    ),
                    data=("database", session_id),
                )
                nodes_by_target.setdefault(("database", session_id), child)

        if selected in nodes_by_target:
            tree.select_node(nodes_by_target[selected])

    @staticmethod
    def _opening_label(opening: dict[str, Any], now: float) -> Text:
        input_path = opening.get("input_path") or "unknown input"
        started_at = float(opening.get("started_at", now))
        label = Text()
        label.append("↻ OPENING", style="bold yellow")
        label.append(f" {input_path} · age {format_duration(now - started_at)}")
        if opening.get("run_auto_analysis"):
            label.append(" · auto-analysis", style="yellow")
        return label

    def _agent_label(
        self,
        alias: str,
        transport: dict[str, Any] | None,
        now: float,
    ) -> Text:
        label = Text()
        label.append(alias, style="bold cyan")
        if transport is None:
            label.append(" orphan · ORPHAN", style="yellow")
            return label

        client_name = transport.get("client_name") or "unknown"
        label.append(f" {client_name}")
        label.append(f" · {str(transport.get('transport', '?')).upper()}")
        state = str(transport.get("state", "OPEN"))
        label.append(f" · {state}", style="yellow" if state == "CLOSING" else "green")
        created_at = float(transport.get("created_at", now))
        label.append(f" · age {format_duration(now - created_at)}")
        active_requests = int(transport.get("active_requests", 0))
        if active_requests:
            label.append(f" · busy({active_requests})", style="yellow")
        else:
            last_activity = float(transport.get("last_activity", now))
            label.append(f" · idle {format_duration(now - last_activity)}")
        return label

    def _database_label(
        self,
        session_id: str,
        database: dict[str, Any] | None,
        *,
        bound: bool,
    ) -> Text:
        alias = self.aliases.database(session_id)
        label = Text()
        label.append("* " if bound else "  ", style="bold magenta" if bound else None)
        label.append(alias, style="bold magenta")
        if database is None:
            label.append(" pending · UNKNOWN", style="yellow")
            return label
        filename = database.get("filename") or session_id
        kind = "GUI" if database.get("is_external") else "LOCAL"
        state = database.get("state", "OPEN")
        refcount = database.get("refcount", 0)
        label.append(f" {filename} · {kind} · {state} · ref {refcount}")
        return label
