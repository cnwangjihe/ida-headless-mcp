"""Thread-safe event payloads used by the local pool administration UI."""

from __future__ import annotations

import queue
import threading
from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class AdminEvent:
    """One incremental update to an entity shown by the local administration UI."""

    source: str
    kind: str
    revision: int
    entity_id: str
    payload: dict[str, Any]


AdminEventSink = Callable[[AdminEvent], None]


class AdminEventBus:
    """Lossless local queue bridging worker threads to one UI consumer."""

    _STOP = object()

    def __init__(self) -> None:
        self._queue: queue.SimpleQueue[AdminEvent | object] = queue.SimpleQueue()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    def publish(self, event: AdminEvent) -> None:
        self._queue.put(event)

    def start(self, consumer: AdminEventSink) -> None:
        with self._lock:
            if self._thread is not None:
                raise RuntimeError("Administration event bus is already running")

            def consume() -> None:
                while True:
                    event = self._queue.get()
                    if event is self._STOP:
                        return
                    consumer(event)  # type: ignore[arg-type]

            self._thread = threading.Thread(
                target=consume,
                name="ida-mcp-admin-events",
                daemon=True,
            )
            self._thread.start()

    def stop(self, *, wait: bool = True) -> None:
        with self._lock:
            thread = self._thread
            if thread is None:
                return
            self._thread = None
            self._queue.put(self._STOP)
        if wait and thread is not threading.current_thread():
            thread.join(timeout=2)
