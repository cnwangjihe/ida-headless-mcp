import logging
import threading
import unittest

from textual.widgets import RichLog, Tree

from ida_pro_mcp.admin_events import AdminEvent, AdminEventBus
from ida_pro_mcp.pool_tui import (
    BufferedLogHandler,
    DashboardModel,
    PoolTuiApp,
    StableAliases,
    format_duration,
)


def event(source, kind, revision, entity_id, **payload):
    return AdminEvent(source, kind, revision, entity_id, payload)


class DashboardModelTests(unittest.TestCase):
    def test_incremental_events_build_and_remove_relationship_state(self):
        model = DashboardModel()
        self.assertTrue(
            model.apply(
                event(
                    "mcp",
                    "TransportOpened",
                    1,
                    "http:agent-a",
                    state="OPEN",
                )
            )
        )
        model.apply(
            event(
                "pool",
                "IdbOpened",
                1,
                "db-a",
                state="OPEN",
                refcount=1,
            )
        )
        model.apply(
            event(
                "pool",
                "ContextMappingChanged",
                2,
                "http:agent-a",
                bound_session_id="db-a",
                held_session_ids=["db-a"],
            )
        )

        self.assertEqual(model.agent_ids(), {"http:agent-a"})
        self.assertIn("db-a", model.databases)

        self.assertFalse(
            model.apply(
                event(
                    "pool",
                    "ContextMappingChanged",
                    1,
                    "http:agent-a",
                    bound_session_id=None,
                    held_session_ids=[],
                )
            )
        )
        self.assertEqual(
            model.contexts["http:agent-a"]["held_session_ids"], ["db-a"]
        )

        model.apply(
            event(
                "pool",
                "ContextMappingChanged",
                3,
                "http:agent-a",
                bound_session_id=None,
                held_session_ids=[],
            )
        )
        model.apply(
            event(
                "pool",
                "IdbClosed",
                4,
                "db-a",
                state="CLOSED",
            )
        )
        model.apply(
            event(
                "mcp",
                "TransportClosed",
                2,
                "http:agent-a",
                state="CLOSED",
            )
        )
        self.assertEqual(model.agent_ids(), set())
        self.assertEqual(model.databases, {})

    def test_context_without_transport_is_retained_as_orphan(self):
        model = DashboardModel()
        model.apply(
            event(
                "pool",
                "ContextMappingChanged",
                1,
                "http:orphan",
                bound_session_id="db-a",
                held_session_ids=["db-a"],
            )
        )
        self.assertEqual(model.agent_ids(), {"http:orphan"})


class PresentationHelpersTests(unittest.TestCase):
    def test_duration_is_minute_granularity(self):
        self.assertEqual(format_duration(0), "<1m")
        self.assertEqual(format_duration(59), "<1m")
        self.assertEqual(format_duration(17 * 60), "17m")
        self.assertEqual(format_duration((2 * 60 + 13) * 60), "2h13m")
        self.assertEqual(format_duration((3 * 24 + 4) * 60 * 60), "3d4h")

    def test_aliases_are_stable_and_not_reused(self):
        aliases = StableAliases()
        self.assertEqual(aliases.agent("a"), "A01")
        self.assertEqual(aliases.agent("b"), "A02")
        self.assertEqual(aliases.agent("a"), "A01")
        self.assertEqual(aliases.database("x"), "D01")
        self.assertEqual(aliases.database("y"), "D02")

    def test_log_handler_is_bounded_and_reports_overwrite(self):
        handler = BufferedLogHandler(capacity=2)
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger = logging.getLogger("test.tui.buffer")
        logger.handlers = [handler]
        logger.propagate = False
        logger.setLevel(logging.INFO)
        try:
            logger.info("one")
            logger.info("two")
            logger.info("three")
        finally:
            logger.handlers = []

        records, dropped = handler.drain()
        self.assertEqual(records, ["two", "three"])
        self.assertEqual(dropped, 1)
        self.assertEqual(handler.drain(), ([], 0))

    def test_event_bus_delivers_all_local_events(self):
        bus = AdminEventBus()
        received = []
        delivered = threading.Event()

        def consume(admin_event):
            received.append(admin_event)
            if len(received) == 3:
                delivered.set()

        bus.start(consume)
        try:
            for revision in range(1, 4):
                bus.publish(event("mcp", "TransportOpened", revision, str(revision)))
            self.assertTrue(delivered.wait(1))
        finally:
            bus.stop()
        self.assertEqual([item.revision for item in received], [1, 2, 3])


class PoolTuiAppTests(unittest.IsolatedAsyncioTestCase):
    async def test_tree_renders_agent_to_shared_database_relationship(self):
        bus = AdminEventBus()
        handler = BufferedLogHandler()
        app = PoolTuiApp(bus, handler)

        async with app.run_test(size=(120, 35)) as pilot:
            now = __import__("time").monotonic()
            for index, context_id in enumerate(
                ("http:agent-a", "sse:agent-b"), start=1
            ):
                bus.publish(
                    event(
                        "mcp",
                        "TransportOpened",
                        index,
                        context_id,
                        context_id=context_id,
                        transport=context_id.split(":", 1)[0],
                        client_name=f"client-{index}",
                        state="OPEN",
                        created_at=now - 600,
                        last_activity=now - 120,
                        active_requests=0,
                    )
                )
            bus.publish(
                event(
                    "pool",
                    "IdbOpened",
                    1,
                    "shared-db",
                    filename="shared.i64",
                    is_external=False,
                    state="OPEN",
                    refcount=2,
                )
            )
            for revision, context_id in enumerate(
                ("http:agent-a", "sse:agent-b"), start=2
            ):
                bus.publish(
                    event(
                        "pool",
                        "ContextMappingChanged",
                        revision,
                        context_id,
                        bound_session_id=(
                            "shared-db" if context_id == "http:agent-a" else None
                        ),
                        held_session_ids=["shared-db"],
                    )
                )

            await pilot.pause()
            tree = app.query_one("#session-tree", Tree)
            self.assertIn("MCP 2", tree.root.label.plain)
            self.assertIn("IDB 1", tree.root.label.plain)
            agent_nodes = [
                node
                for node in tree.root.children
                if node.data and node.data[0] == "agent"
            ]
            self.assertEqual(len(agent_nodes), 2)
            child_labels = [
                child.label.plain
                for node in agent_nodes
                for child in node.children
            ]
            self.assertEqual(sum("D01" in label for label in child_labels), 2)
            self.assertEqual(sum(label.startswith("* ") for label in child_labels), 1)

    async def test_tree_handles_expected_ten_agents_and_thirty_databases(self):
        bus = AdminEventBus()
        app = PoolTuiApp(bus, BufferedLogHandler())

        async with app.run_test(size=(160, 45)) as pilot:
            now = __import__("time").monotonic()
            held_by_agent = {index: [] for index in range(10)}
            for index in range(30):
                session_id = f"db-{index}"
                held_by_agent[index % 10].append(session_id)
                bus.publish(
                    event(
                        "pool",
                        "IdbOpened",
                        index + 1,
                        session_id,
                        filename=f"sample-{index}.i64",
                        is_external=False,
                        state="OPEN",
                        refcount=1,
                    )
                )
            for index in range(10):
                context_id = f"http:agent-{index}"
                bus.publish(
                    event(
                        "mcp",
                        "TransportOpened",
                        index + 1,
                        context_id,
                        transport="http",
                        client_name=f"agent-{index}",
                        state="OPEN",
                        created_at=now,
                        last_activity=now,
                        active_requests=0,
                    )
                )
                bus.publish(
                    event(
                        "pool",
                        "ContextMappingChanged",
                        index + 31,
                        context_id,
                        bound_session_id=held_by_agent[index][0],
                        held_session_ids=held_by_agent[index],
                    )
                )

            await pilot.pause()
            tree = app.query_one("#session-tree", Tree)
            self.assertIn("MCP 10", tree.root.label.plain)
            self.assertIn("IDB 30", tree.root.label.plain)
            agent_nodes = [
                node
                for node in tree.root.children
                if node.data and node.data[0] == "agent"
            ]
            self.assertEqual(len(agent_nodes), 10)
            self.assertEqual(sum(len(node.children) for node in agent_nodes), 30)

    async def test_startup_logs_are_drained_into_main_log(self):
        bus = AdminEventBus()
        handler = BufferedLogHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
        record = logging.LogRecord(
            "ida_mcp.pool.session",
            logging.INFO,
            __file__,
            1,
            "backend ready",
            (),
            None,
        )
        handler.emit(record)
        app = PoolTuiApp(bus, handler)

        async with app.run_test(size=(80, 24)) as pilot:
            app._drain_logs()
            await pilot.pause()
            log = app.query_one("#main-log", RichLog)
            self.assertTrue(any("backend ready" in line.text for line in log.lines))


if __name__ == "__main__":
    unittest.main()
