"""Event-driven local administration interface for the idalib pool."""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from rich.text import Text
from textual.app import App, ComposeResult
from textual.widgets import RichLog, Tree

from ida_pro_mcp.admin_events import AdminEvent, AdminEventBus


logger = logging.getLogger("ida_mcp.tui")


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
    _revisions: dict[tuple[str, str], int] = field(default_factory=dict)

    def apply(self, event: AdminEvent) -> bool:
        if event.source == "mcp":
            entity_type = "transport"
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
        return set(self.transports) | {
            context_id
            for context_id, context in self.contexts.items()
            if self._context_has_relations(context)
        }


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
    """

    def __init__(
        self,
        event_bus: AdminEventBus,
        log_handler: BufferedLogHandler,
    ) -> None:
        super().__init__()
        self.event_bus = event_bus
        self.log_handler = log_handler
        self.model = DashboardModel()
        self.aliases = StableAliases()
        self.runtime_state = "STARTING"
        self.runtime_detail = ""
        self._collapsed_agents: set[str] = set()
        self._event_bridge_started = False

    def compose(self) -> ComposeResult:
        yield Tree[TreeTarget]("Sessions", id="session-tree")
        yield RichLog(
            max_lines=2000,
            wrap=False,
            markup=False,
            auto_scroll=True,
            id="main-log",
        )

    def on_mount(self) -> None:
        tree = self.query_one("#session-tree", Tree)
        tree.root.expand()
        self._rebuild_tree()
        self.event_bus.start(self._deliver_admin_event)
        self._event_bridge_started = True
        self.set_interval(60, self._refresh_durations, name="duration-refresh")
        self.set_interval(0.1, self._drain_logs, name="log-drain")

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
        if event.source == "pool" and event.kind != "ContextMappingChanged":
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
        if self.runtime_detail:
            root_label.append(f" · {self.runtime_detail}")
        tree.root.set_label(root_label)
        tree.root.expand()

        nodes_by_target: dict[TreeTarget, Any] = {}
        referenced_databases: set[str] = set()
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
            if not session_ids:
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
