"""Thread-safe event payloads used by the local pool administration UI."""

from __future__ import annotations

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
