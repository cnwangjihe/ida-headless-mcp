import logging
import threading
import unittest
from unittest.mock import MagicMock

from textual.widgets import Input, RichLog, Tree

from ida_pro_mcp.admin_events import AdminEvent, AdminEventBus
from ida_pro_mcp.pool_tui import (
    BufferedLogHandler,
    ConfirmActionScreen,
    DashboardModel,
    PoolTuiApp,
    StableAliases,
    format_duration,
    format_memory_size,
    format_metric_duration,
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

    def test_opening_lifecycle_is_tracked_separately_from_databases(self):
        model = DashboardModel()
        started = event(
            "pool",
            "IdbOpenStarted",
            4,
            "open:1234",
            context_id="http:agent-a",
            input_path="/firmware/router.i64",
            started_at=100.0,
        )

        self.assertTrue(model.apply(started))
        self.assertEqual(model.agent_ids(), {"http:agent-a"})
        self.assertEqual(
            model.openings["open:1234"]["input_path"],
            "/firmware/router.i64",
        )
        self.assertEqual(model.databases, {})

        self.assertTrue(
            model.apply(
                event(
                    "pool",
                    "IdbOpenFinished",
                    6,
                    "open:1234",
                    success=False,
                )
            )
        )
        self.assertEqual(model.openings, {})
        self.assertFalse(model.apply(started))

    def test_request_lifecycle_tracks_busy_target_and_cleans_on_close(self):
        model = DashboardModel()
        started = event(
            "pool",
            "IdbRequestStarted",
            5,
            "request:1234",
            session_id="db-a",
            context_id="http:agent-a",
            operation="decompile",
            started_at=100.0,
        )

        self.assertTrue(model.apply(started))
        self.assertEqual(model.agent_ids(), {"http:agent-a"})
        self.assertEqual(
            model.requests["request:1234"]["session_id"],
            "db-a",
        )

        model.apply(event("pool", "IdbClosed", 6, "db-a", state="CLOSED"))
        self.assertEqual(model.requests, {})
        self.assertFalse(model.apply(started))

    def test_completed_calls_accumulate_session_statistics(self):
        model = DashboardModel()
        model.apply(event("pool", "IdbOpened", 1, "db-a", state="OPEN"))

        for revision, operation, started_at, finished_at in (
            (2, "decompile", 100.0, 102.5),
            (4, "get_functions", 110.0, 110.5),
        ):
            operation_id = f"request:{revision}"
            model.apply(
                event(
                    "pool",
                    "IdbRequestStarted",
                    revision,
                    operation_id,
                    session_id="db-a",
                    context_id="http:agent-a",
                    operation=operation,
                    started_at=started_at,
                )
            )
            model.apply(
                event(
                    "pool",
                    "IdbRequestFinished",
                    revision + 1,
                    operation_id,
                    session_id="db-a",
                    context_id="http:agent-a",
                    operation=operation,
                    started_at=started_at,
                    finished_at=finished_at,
                    success=True,
                )
            )

        stats = model.session_stats["db-a"]
        self.assertEqual(stats["completed_calls"], 2)
        self.assertEqual(stats["total_duration"], 3.0)
        self.assertEqual(stats["max_duration"], 2.5)
        self.assertEqual(stats["last_operation"], "get_functions")
        self.assertEqual(stats["last_context_id"], "http:agent-a")
        self.assertEqual(stats["last_finished_at"], 110.5)


class PresentationHelpersTests(unittest.TestCase):
    def test_duration_is_minute_granularity(self):
        self.assertEqual(format_duration(0), "<1m")
        self.assertEqual(format_duration(59), "<1m")
        self.assertEqual(format_duration(17 * 60), "17m")
        self.assertEqual(format_duration((2 * 60 + 13) * 60), "2h13m")
        self.assertEqual(format_duration((3 * 24 + 4) * 60 * 60), "3d4h")

    def test_metric_duration_adapts_to_request_latency(self):
        self.assertEqual(format_metric_duration(0.125), "125ms")
        self.assertEqual(format_metric_duration(2.25), "2.2s")
        self.assertEqual(format_metric_duration(90), "1.5m")
        self.assertEqual(format_metric_duration(2 * 60 * 60), "2.0h")

    def test_memory_size_uses_compact_binary_units(self):
        self.assertEqual(format_memory_size(None), "-")
        self.assertEqual(format_memory_size(0), "0 B")
        self.assertEqual(format_memory_size(1536), "1.5 KiB")
        self.assertEqual(format_memory_size(512 * 1024 * 1024), "512 MiB")
        self.assertEqual(format_memory_size(3 * 1024 * 1024 * 1024), "3.0 GiB")

    def test_aliases_are_stable_unbounded_and_not_reused(self):
        aliases = StableAliases()
        self.assertEqual(aliases.agent("a"), "A001")
        self.assertEqual(aliases.agent("b"), "A002")
        self.assertEqual(aliases.agent("a"), "A001")
        self.assertEqual(aliases.database("x"), "D001")
        self.assertEqual(aliases.database("y"), "D002")
        for index in range(998):
            aliases.agent(f"agent-{index}")
            aliases.database(f"database-{index}")
        self.assertEqual(aliases.agent("agent-997"), "A1000")
        self.assertEqual(aliases.database("database-997"), "D1000")

    def test_aliases_resolve_exact_ids_and_unique_prefixes(self):
        aliases = StableAliases()
        aliases.agent("http:agent-alpha")
        aliases.agent("http:agent-beta")
        aliases.database("firmware-a")
        self.assertEqual(
            aliases.resolve_agent(
                "A001", {"http:agent-alpha", "http:agent-beta"}
            ),
            "http:agent-alpha",
        )
        self.assertEqual(
            aliases.resolve_database("firm", {"firmware-a"}),
            "firmware-a",
        )
        with self.assertRaisesRegex(ValueError, "Ambiguous"):
            aliases.resolve_agent(
                "http:agent", {"http:agent-alpha", "http:agent-beta"}
            )

    def test_database_name_starting_with_alias_letter_resolves_as_session(self):
        aliases = StableAliases()
        aliases.agent("http:agent-alpha")

        self.assertEqual(
            aliases.resolve_any(
                "a_binary_deadbeef",
                {"http:agent-alpha"},
                {"a_binary_deadbeef"},
            ),
            ("database", "a_binary_deadbeef"),
        )

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
    async def test_command_input_keeps_focus_when_other_panes_are_clicked(self):
        app = PoolTuiApp(AdminEventBus(), BufferedLogHandler())

        async with app.run_test(size=(100, 30)) as pilot:
            command_input = app.query_one("#command-input", Input)
            tree = app.query_one("#session-tree", Tree)
            log = app.query_one("#main-log", RichLog)
            self.assertIs(app.screen.focused, command_input)
            self.assertTrue(tree.root.is_expanded)

            await pilot.click(tree, offset=(2, 1))
            await pilot.pause()
            self.assertFalse(tree.root.is_expanded)
            self.assertIs(app.screen.focused, command_input)

            await pilot.click(log, offset=(5, 2))
            await pilot.pause()
            self.assertIs(app.screen.focused, command_input)

            await pilot.press("tab")
            self.assertIs(app.screen.focused, command_input)

    async def test_event_bridge_starts_before_runtime_bootstrap(self):
        order = []
        bus = MagicMock()
        bus.start.side_effect = lambda callback: order.append("events")
        app = PoolTuiApp(
            bus,
            BufferedLogHandler(),
            startup_callback=lambda: order.append("runtime"),
        )

        async with app.run_test():
            self.assertEqual(order, ["events", "runtime"])

    async def test_page_keys_scroll_log_without_moving_command_focus(self):
        app = PoolTuiApp(AdminEventBus(), BufferedLogHandler())

        async with app.run_test(size=(100, 30)) as pilot:
            command_input = app.query_one("#command-input", Input)
            log = app.query_one("#main-log", RichLog)
            for index in range(100):
                log.write(f"line {index}")
            await pilot.pause()
            log.scroll_end(animate=False, immediate=True)
            await pilot.pause()
            bottom = log.scroll_y
            self.assertGreater(bottom, 0)

            await pilot.press("pageup")
            await pilot.pause()
            self.assertLess(log.scroll_y, bottom)
            self.assertIs(app.screen.focused, command_input)

            await pilot.press("pagedown")
            await pilot.pause()
            self.assertGreater(log.scroll_y, 0)
            self.assertIs(app.screen.focused, command_input)

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
                    memory_rss_bytes=512 * 1024 * 1024,
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
            self.assertEqual(sum("D001" in label for label in child_labels), 2)
            self.assertEqual(sum("[shared-db]" in label for label in child_labels), 2)
            self.assertEqual(sum("RSS 512 MiB" in label for label in child_labels), 2)
            self.assertEqual(sum(label.startswith("* ") for label in child_labels), 1)

    async def test_tree_shows_in_progress_open_under_requesting_agent(self):
        app = PoolTuiApp(AdminEventBus(), BufferedLogHandler())

        async with app.run_test(size=(140, 35)) as pilot:
            now = __import__("time").monotonic()
            app.apply_admin_event(
                event(
                    "mcp",
                    "TransportOpened",
                    1,
                    "http:agent-a",
                    transport="http",
                    client_name="agent-a",
                    state="OPEN",
                    created_at=now,
                    last_activity=now,
                    active_requests=1,
                )
            )
            app.apply_admin_event(
                event(
                    "pool",
                    "IdbOpenStarted",
                    2,
                    "open:1234",
                    context_id="http:agent-a",
                    input_path="/firmware/router.i64",
                    started_at=now,
                    run_auto_analysis=True,
                )
            )
            await pilot.pause()

            tree = app.query_one("#session-tree", Tree)
            self.assertIn("OPENING 1", tree.root.label.plain)
            agent = next(
                node
                for node in tree.root.children
                if node.data == ("agent", "http:agent-a")
            )
            self.assertEqual(len(agent.children), 1)
            self.assertIn("OPENING", agent.children[0].label.plain)
            self.assertIn("/firmware/router.i64", agent.children[0].label.plain)
            self.assertEqual(app.aliases.database_items(), ())
            with self.assertLogs("ida_mcp.tui", level="INFO") as captured:
                app.execute_command("show A001")
            self.assertIn("/firmware/router.i64", captured.output[0])

            app.apply_admin_event(
                event(
                    "pool",
                    "IdbOpened",
                    3,
                    "database-a",
                    filename="router.i64",
                    input_path="/firmware/router.i64",
                    state="OPEN",
                    refcount=1,
                )
            )
            app.apply_admin_event(
                event(
                    "pool",
                    "ContextMappingChanged",
                    4,
                    "http:agent-a",
                    bound_session_id="database-a",
                    held_session_ids=["database-a"],
                )
            )
            app.apply_admin_event(
                event(
                    "pool",
                    "IdbOpenFinished",
                    5,
                    "open:1234",
                    success=True,
                    session_id="database-a",
                )
            )
            await pilot.pause()

            self.assertNotIn("OPENING", tree.root.label.plain)
            agent = next(
                node
                for node in tree.root.children
                if node.data == ("agent", "http:agent-a")
            )
            self.assertEqual(len(agent.children), 1)
            self.assertIn(
                "D001 [database-a] router.i64",
                agent.children[0].label.plain,
            )
            self.assertIn("calls 1", agent.children[0].label.plain)

    async def test_tree_marks_the_target_database_busy(self):
        app = PoolTuiApp(AdminEventBus(), BufferedLogHandler())

        async with app.run_test(size=(140, 35)) as pilot:
            now = __import__("time").monotonic()
            app.apply_admin_event(
                event(
                    "mcp",
                    "TransportOpened",
                    1,
                    "http:agent-a",
                    transport="http",
                    client_name="agent-a",
                    state="OPEN",
                    created_at=now,
                    last_activity=now,
                    active_requests=1,
                )
            )
            app.apply_admin_event(
                event(
                    "pool",
                    "IdbOpened",
                    2,
                    "database-a",
                    filename="router.i64",
                    state="OPEN",
                    refcount=1,
                )
            )
            app.apply_admin_event(
                event(
                    "pool",
                    "ContextMappingChanged",
                    3,
                    "http:agent-a",
                    bound_session_id="database-a",
                    held_session_ids=["database-a"],
                )
            )
            app.apply_admin_event(
                event(
                    "pool",
                    "IdbRequestStarted",
                    4,
                    "request:1234",
                    session_id="database-a",
                    context_id="http:agent-a",
                    operation="decompile",
                    started_at=now,
                    memory_rss_bytes=768 * 1024 * 1024,
                )
            )
            await pilot.pause()

            tree = app.query_one("#session-tree", Tree)
            agent = next(
                node
                for node in tree.root.children
                if node.data == ("agent", "http:agent-a")
            )
            database_label = agent.children[0].label.plain
            self.assertIn("D001 [database-a] router.i64", database_label)
            self.assertIn("RSS 768 MiB", database_label)
            self.assertIn("BUSY decompile", database_label)
            self.assertEqual(
                app.aliases.database_items(),
                (("database-a", "D001"),),
            )
            with self.assertLogs("ida_mcp.tui", level="INFO") as captured:
                app.execute_command("show D001")
            self.assertIn("request:1234 decompile@http:agent-a", captured.output[0])

            app.apply_admin_event(
                event(
                    "pool",
                    "IdbRequestFinished",
                    5,
                    "request:1234",
                    session_id="database-a",
                    context_id="http:agent-a",
                    operation="decompile",
                    started_at=now,
                    finished_at=now + 2.5,
                    success=True,
                    memory_rss_bytes=1024 * 1024 * 1024,
                )
            )
            await pilot.pause()

            agent = next(
                node
                for node in tree.root.children
                if node.data == ("agent", "http:agent-a")
            )
            self.assertNotIn("BUSY", agent.children[0].label.plain)
            self.assertIn("RSS 1.0 GiB", agent.children[0].label.plain)
            self.assertIn("calls 1", agent.children[0].label.plain)
            with self.assertLogs("ida_mcp.tui", level="INFO") as captured:
                app.execute_command("show D001")
            self.assertIn("calls: 1", captured.output[0])
            self.assertIn("total 2.5s · avg 2.5s · max 2.5s", captured.output[0])

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


class PoolTuiCommandTests(unittest.IsolatedAsyncioTestCase):
    def _database_event(self, *, external=False, revision=1):
        return event(
            "pool",
            "ExternalIdbRegistered" if external else "IdbOpened",
            revision,
            "database-a",
            session_id="database-a",
            filename="sample.i64",
            input_path="/tmp/sample.elf",
            idb_path="/tmp/sample.i64",
            is_external=external,
            state="OPEN",
            refcount=1,
            instance_index=0,
            pid=1234,
            log_path="/tmp/0.log",
        )

    async def test_save_action_calls_pool_without_changing_ui_state(self):
        bus = AdminEventBus()
        pool = MagicMock()
        pool.save_session.return_value = {"success": True}
        app = PoolTuiApp(
            bus,
            BufferedLogHandler(),
            mcp_server=MagicMock(),
            pool_manager=pool,
        )

        async with app.run_test(size=(120, 35)) as pilot:
            app.apply_admin_event(self._database_event())
            result = app._perform_admin_action(
                "save", ("database", "database-a")
            )
            await pilot.pause()

            self.assertTrue(result["success"])
            pool.save_session.assert_called_once_with("database-a")
            self.assertEqual(
                app.query_one("#command-input", Input).region.height,
                1,
            )

    async def test_tab_completes_commands_and_context_appropriate_targets(self):
        app = PoolTuiApp(AdminEventBus(), BufferedLogHandler())

        async with app.run_test(size=(120, 35)) as pilot:
            command_input = app.query_one("#command-input", Input)
            command_input.value = "disc"
            command_input.cursor_position = len(command_input.value)
            await pilot.press("tab")
            self.assertEqual(command_input.value, "disconnect ")

            app.apply_admin_event(
                event(
                    "mcp",
                    "TransportOpened",
                    1,
                    "http:agent-a",
                    state="OPEN",
                )
            )
            app.apply_admin_event(self._database_event())
            app.apply_admin_event(
                event(
                    "pool",
                    "ExternalIdbRegistered",
                    2,
                    "database-gui",
                    is_external=True,
                    state="OPEN",
                    refcount=1,
                )
            )

            command_input.value = "disconnect A"
            command_input.cursor_position = len(command_input.value)
            await pilot.press("tab")
            self.assertEqual(command_input.value, "disconnect A001 ")

            command_input.value = "close D"
            command_input.cursor_position = len(command_input.value)
            await pilot.press("tab")
            self.assertEqual(command_input.value, "close D001 ")

            command_input.value = "unregister D"
            command_input.cursor_position = len(command_input.value)
            await pilot.press("tab")
            self.assertEqual(command_input.value, "unregister D002 ")

    async def test_tab_expands_common_prefix_then_cycles_candidates(self):
        app = PoolTuiApp(AdminEventBus(), BufferedLogHandler())

        async with app.run_test(size=(120, 35)) as pilot:
            command_input = app.query_one("#command-input", Input)
            command_input.value = "c"
            command_input.cursor_position = 1

            await pilot.press("tab")
            self.assertEqual(command_input.value, "cl")
            await pilot.press("tab")
            self.assertEqual(command_input.value, "close")
            await pilot.press("tab")
            self.assertEqual(command_input.value, "clear")

    async def test_close_command_requires_confirmation(self):
        bus = AdminEventBus()
        pool = MagicMock()
        pool.close_session.return_value = {"success": True}
        app = PoolTuiApp(
            bus,
            BufferedLogHandler(),
            mcp_server=MagicMock(),
            pool_manager=pool,
        )

        async with app.run_test(size=(120, 35)) as pilot:
            app.apply_admin_event(self._database_event())
            app._run_admin_action = MagicMock()
            try:
                app.execute_command("close D001")
                await pilot.pause()
                app._run_admin_action.assert_not_called()

                await pilot.click("#confirm")
                await pilot.pause()
                app._run_admin_action.assert_called_once_with(
                    "close", ("database", "database-a")
                )
            finally:
                app._busy_targets.clear()

    async def test_confirmation_is_fully_keyboard_operable(self):
        app = PoolTuiApp(
            AdminEventBus(),
            BufferedLogHandler(),
            mcp_server=MagicMock(),
            pool_manager=MagicMock(),
        )

        async with app.run_test(size=(120, 35)) as pilot:
            app.apply_admin_event(self._database_event())
            app._run_admin_action = MagicMock()
            try:
                app.execute_command("close D001")
                await pilot.pause()
                self.assertIsInstance(app.screen, ConfirmActionScreen)
                self.assertEqual(app.screen.focused.id, "cancel")

                await pilot.press("tab")
                await pilot.pause()
                self.assertEqual(app.screen.focused.id, "confirm")

                await pilot.press("enter")
                await pilot.pause()
                app._run_admin_action.assert_called_once_with(
                    "close", ("database", "database-a")
                )
            finally:
                app._busy_targets.clear()

    async def test_confirmation_supports_y_and_n_shortcuts(self):
        app = PoolTuiApp(
            AdminEventBus(),
            BufferedLogHandler(),
            mcp_server=MagicMock(),
            pool_manager=MagicMock(),
        )

        async with app.run_test(size=(120, 35)) as pilot:
            app.apply_admin_event(self._database_event())
            app._run_admin_action = MagicMock()
            try:
                app.execute_command("close D001")
                await pilot.pause()
                await pilot.press("n")
                await pilot.pause()
                app._run_admin_action.assert_not_called()

                app.execute_command("close D001")
                await pilot.pause()
                await pilot.press("y")
                await pilot.pause()
                app._run_admin_action.assert_called_once_with(
                    "close", ("database", "database-a")
                )
            finally:
                app._busy_targets.clear()

    async def test_database_ownership_restricts_destructive_commands(self):
        bus = AdminEventBus()
        app = PoolTuiApp(
            bus,
            BufferedLogHandler(),
            mcp_server=MagicMock(),
            pool_manager=MagicMock(),
        )

        async with app.run_test(size=(120, 35)):
            app.apply_admin_event(self._database_event(external=True))
            app.push_screen = MagicMock()
            with self.assertLogs("ida_mcp.tui", level="ERROR") as captured:
                app.execute_command("close D001")
            self.assertIn("cannot be force-closed", captured.output[0])
            app.push_screen.assert_not_called()

            app.apply_admin_event(
                event(
                    "pool",
                    "ExternalIdbUnregistered",
                    2,
                    "database-a",
                    state="CLOSED",
                )
            )
            app.apply_admin_event(self._database_event(revision=3))
            with self.assertLogs("ida_mcp.tui", level="ERROR") as captured:
                app.execute_command("unregister D001")
            self.assertIn("cannot be unregistered", captured.output[0])
            app.push_screen.assert_not_called()

    async def test_disconnect_orphan_falls_back_to_context_release(self):
        bus = AdminEventBus()
        pool = MagicMock()
        pool.release_context.return_value = {
            "success": True,
            "released_sessions": ["database-a"],
        }
        mcp = MagicMock()
        mcp.disconnect_transport_session.return_value = {
            "success": False,
            "error": "Transport session not found: http:orphan",
        }
        app = PoolTuiApp(
            bus,
            BufferedLogHandler(),
            mcp_server=mcp,
            pool_manager=pool,
        )

        async with app.run_test(size=(120, 35)):
            app.apply_admin_event(self._database_event())
            app.apply_admin_event(
                event(
                    "pool",
                    "ContextMappingChanged",
                    2,
                    "http:orphan",
                    bound_session_id="database-a",
                    held_session_ids=["database-a"],
                )
            )
            result = app._perform_admin_action(
                "disconnect", ("agent", "http:orphan")
            )

            self.assertTrue(result["success"])
            mcp.disconnect_transport_session.assert_called_once_with("http:orphan")
            pool.release_context.assert_called_once_with("http:orphan")


if __name__ == "__main__":
    unittest.main()
