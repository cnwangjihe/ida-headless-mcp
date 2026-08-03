import multiprocessing
import threading
import unittest

from ida_pro_mcp.backend_ipc import (
    BackendIpcServer,
    BackendProcessExited,
    BackendProtocolError,
    make_message,
    receive_message,
    send_message,
    wait_for_message,
)


def _fake_backend(rpc_connection, control_connection):
    server = BackendIpcServer(
        rpc_connection,
        control_connection,
        dispatch=lambda request: {"echo": request},
        cancel_pending=lambda: 0,
    )
    try:
        server.serve(ready_fields={"worker": "fake"})
    finally:
        rpc_connection.close()
        control_connection.close()


def _exit_without_message(rpc_connection, control_connection):
    rpc_connection.close()
    control_connection.close()


def _cancellable_fake_backend(rpc_connection, control_connection):
    cancelled = threading.Event()

    def dispatch(request):
        cancelled.wait(5)
        return {"cancelled": cancelled.is_set(), "request": request}

    def cancel_pending():
        cancelled.set()
        return 1

    server = BackendIpcServer(
        rpc_connection,
        control_connection,
        dispatch=dispatch,
        cancel_pending=cancel_pending,
    )
    try:
        server.serve()
    finally:
        rpc_connection.close()
        control_connection.close()


class BackendIpcTests(unittest.TestCase):
    def setUp(self):
        self.context = multiprocessing.get_context("spawn")

    def test_messages_use_json_bytes(self):
        receiver, sender = self.context.Pipe(duplex=False)
        try:
            send_message(sender, make_message("request", payload={"text": "你好"}))
            message = receive_message(receiver)
        finally:
            receiver.close()
            sender.close()

        self.assertEqual(message["type"], "request")
        self.assertEqual(message["payload"], {"text": "你好"})

    def test_receive_rejects_invalid_protocol(self):
        receiver, sender = self.context.Pipe(duplex=False)
        try:
            sender.send_bytes(b'{"type":"ready","protocol":99}')
            with self.assertRaisesRegex(BackendProtocolError, "unsupported"):
                receive_message(receiver)
        finally:
            receiver.close()
            sender.close()

    def test_spawn_worker_round_trip_and_graceful_shutdown(self):
        parent_rpc, child_rpc = self.context.Pipe(duplex=True)
        child_control, parent_control = self.context.Pipe(duplex=False)
        process = self.context.Process(
            target=_fake_backend,
            args=(child_rpc, child_control),
        )
        process.start()
        child_rpc.close()
        child_control.close()
        try:
            ready = wait_for_message(parent_rpc, process.sentinel, 5)
            self.assertEqual(ready["type"], "ready")
            self.assertEqual(ready["worker"], "fake")

            request = {"jsonrpc": "2.0", "method": "ping", "id": 7}
            send_message(parent_rpc, make_message("request", payload=request))
            response = wait_for_message(parent_rpc, process.sentinel, 5)
            self.assertEqual(response["type"], "response")
            self.assertEqual(response["payload"], {"echo": request})

            send_message(parent_control, make_message("shutdown"))
            process.join(5)
            self.assertFalse(process.is_alive())
            self.assertEqual(process.exitcode, 0)
        finally:
            if process.is_alive():
                process.terminate()
                process.join(5)
            parent_rpc.close()
            parent_control.close()
            process.close()

    def test_wait_reports_process_exit_before_message(self):
        parent_rpc, child_rpc = self.context.Pipe(duplex=True)
        child_control, parent_control = self.context.Pipe(duplex=False)
        process = self.context.Process(
            target=_exit_without_message,
            args=(child_rpc, child_control),
        )
        process.start()
        child_rpc.close()
        child_control.close()
        try:
            with self.assertRaises(BackendProcessExited):
                wait_for_message(parent_rpc, process.sentinel, 5)
            process.join(5)
        finally:
            if process.is_alive():
                process.terminate()
                process.join(5)
            parent_rpc.close()
            parent_control.close()
            process.close()

    def test_control_pipe_cancels_an_inflight_rpc(self):
        parent_rpc, child_rpc = self.context.Pipe(duplex=True)
        child_control, parent_control = self.context.Pipe(duplex=False)
        process = self.context.Process(
            target=_cancellable_fake_backend,
            args=(child_rpc, child_control),
        )
        process.start()
        child_rpc.close()
        child_control.close()
        try:
            self.assertEqual(
                wait_for_message(parent_rpc, process.sentinel, 5)["type"],
                "ready",
            )
            request = {"jsonrpc": "2.0", "method": "wait", "id": 8}
            send_message(parent_rpc, make_message("request", payload=request))
            send_message(parent_control, make_message("cancel"))

            response = wait_for_message(parent_rpc, process.sentinel, 5)
            self.assertTrue(response["payload"]["cancelled"])

            send_message(parent_control, make_message("shutdown"))
            process.join(5)
            self.assertEqual(process.exitcode, 0)
        finally:
            if process.is_alive():
                process.terminate()
                process.join(5)
            parent_rpc.close()
            parent_control.close()
            process.close()


if __name__ == "__main__":
    unittest.main()
