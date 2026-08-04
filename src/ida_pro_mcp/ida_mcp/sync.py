import logging
import queue
import functools
import os
import sys
import threading
import time
import idaapi
import idc
from .rpc import McpToolError
from .zeromcp.jsonrpc import get_current_cancel_event, RequestCancelledError

# ============================================================================
# IDA Synchronization & Error Handling
# ============================================================================

ida_major = int(idaapi.get_kernel_version().split(".", 1)[0])

# Capture main thread ID at module load time.  In headless idalib mode the
# main thread is the only thread that can call IDA APIs directly, and
# execute_sync() will deadlock if called *from* the main thread (because the
# callback is queued for the same thread that is waiting).  We detect this
# case and execute directly instead.
_main_thread_id = threading.current_thread().ident


class IDAError(McpToolError):
    def __init__(self, message: str):
        super().__init__(message)

    @property
    def message(self) -> str:
        return self.args[0]


class IDASyncError(Exception):
    pass


class CancelledError(RequestCancelledError):
    """Raised when a request is cancelled via notifications/cancelled."""

    pass


logger = logging.getLogger("ida_mcp.ida.sync")
_TOOL_TIMEOUT_ENV = "IDA_MCP_TOOL_TIMEOUT_SEC"
_DEFAULT_TOOL_TIMEOUT_SEC = 60.0
_EXECUTE_SYNC_WAIT_GRACE_SEC = 5.0


def _get_tool_timeout_seconds() -> float:
    value = os.getenv(_TOOL_TIMEOUT_ENV, "").strip()
    if value == "":
        return _DEFAULT_TOOL_TIMEOUT_SEC
    try:
        return float(value)
    except ValueError:
        return _DEFAULT_TOOL_TIMEOUT_SEC


_call_stack = threading.local()


def _current_call_stack() -> list[str]:
    stack = getattr(_call_stack, "data", None)
    if stack is None:
        stack = []
        _call_stack.data = stack
    return stack


def _run_with_batch(ff):
    """Execute *ff* inside batch mode with call-stack reentry detection."""
    stack = _current_call_stack()
    if stack:
        last_func_name = stack[-1]
        error_str = f"Call stack is not empty while calling the function {ff.__name__} from {last_func_name}"
        raise IDASyncError(error_str)

    stack.append(ff.__name__)
    old_batch = None
    batch_enabled = False
    try:
        old_batch = idc.batch(1)
        batch_enabled = True
        return ff()
    finally:
        try:
            if batch_enabled:
                idc.batch(old_batch)
        finally:
            stack.pop()


def _sync_wrapper(ff, wait_timeout: float | None = None):
    """Call a function ff on the IDA main thread in write mode.

    If already on the main thread (common in headless idalib with
    background=False), execute directly to avoid a deadlock where
    execute_sync queues a callback for a thread that is itself waiting.
    """
    if threading.current_thread().ident == _main_thread_id:
        return _run_with_batch(ff)

    res_container = queue.Queue()

    def runned():
        try:
            res_container.put(_run_with_batch(ff))
        except Exception as x:
            res_container.put(x)

    execute_result = idaapi.execute_sync(runned, idaapi.MFF_WRITE)
    if execute_result == -1:
        raise IDASyncError(f"Failed to schedule {ff.__name__} on the IDA main thread")

    queue_timeout = wait_timeout if wait_timeout and wait_timeout > 0 else _DEFAULT_TOOL_TIMEOUT_SEC
    total_wait = queue_timeout + _EXECUTE_SYNC_WAIT_GRACE_SEC
    try:
        res = res_container.get(timeout=total_wait)
    except queue.Empty as e:
        raise IDASyncError(
            f"IDA main-thread callback for {ff.__name__} did not complete "
            f"within {total_wait:.2f}s"
        ) from e
    if isinstance(res, Exception):
        raise res
    return res


def _normalize_timeout(value: object) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def sync_wrapper(ff, timeout_override: float | None = None):
    """Wrapper to enable timeout and cancellation during IDA synchronization.

    Note: Batch mode is now handled in _sync_wrapper to ensure it's always
    applied consistently for all synchronized operations.
    """
    # Capture cancel event from thread-local before execute_sync
    cancel_event = get_current_cancel_event()

    timeout = timeout_override
    if timeout is None:
        timeout = _get_tool_timeout_seconds()
    if timeout > 0 or cancel_event is not None:

        def timed_ff():
            # Calculate deadline when execution starts on IDA main thread,
            # not when the request was queued (avoids stale deadlines)
            deadline = time.monotonic() + timeout if timeout > 0 else None

            def profilefunc(frame, event, arg):
                # Check cancellation first (higher priority)
                if cancel_event is not None and cancel_event.is_set():
                    raise CancelledError("Request was cancelled")
                if deadline is not None and time.monotonic() >= deadline:
                    raise IDASyncError(f"Tool timed out after {timeout:.2f}s")

            old_profile = sys.getprofile()
            sys.setprofile(profilefunc)
            try:
                return ff()
            finally:
                sys.setprofile(old_profile)

        timed_ff.__name__ = ff.__name__
        return _sync_wrapper(timed_ff, timeout)
    return _sync_wrapper(ff, timeout)


def idasync(f):
    """Run the function on the IDA main thread in write mode.

    This is the unified decorator for all IDA synchronization.
    Previously there were separate @idaread and @idawrite decorators,
    but since read-only operations in IDA might actually require write
    access (e.g., decompilation), we now use a single decorator.
    """

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ff = functools.partial(f, *args, **kwargs)
        ff.__name__ = f.__name__
        timeout_override = _normalize_timeout(
            getattr(f, "__ida_mcp_timeout_sec__", None)
        )
        return sync_wrapper(ff, timeout_override)

    return wrapper


def tool_timeout(seconds: float):
    """Decorator to override per-tool timeout (seconds).

    IMPORTANT: Must be applied BEFORE @idasync (i.e., listed AFTER it)
    so the attribute exists when it captures the function in closure.

    Correct order:
        @tool
        @idasync
        @tool_timeout(90.0)  # innermost
        def my_func(...):
    """

    def decorator(func):
        setattr(func, "__ida_mcp_timeout_sec__", seconds)
        return func

    return decorator
