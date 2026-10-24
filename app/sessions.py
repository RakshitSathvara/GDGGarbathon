"""In-memory session store with sliding expiry, a size cap (LRU eviction) and per-session locks.

FastAPI runs the synchronous /api/analyze handler in a threadpool, so each session carries a lock
that serializes chunk processing: the context for chunk N must include chunks 0..N-1.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Generic, TypeVar

T = TypeVar("T")


@dataclass
class _Entry(Generic[T]):
    value: T
    expires_at: float
    lock: threading.Lock = field(default_factory=threading.Lock)


class SessionStore(Generic[T]):
    def __init__(
        self, ttl_s: float, max_sessions: int, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self._ttl_s = ttl_s
        self._max_sessions = max_sessions
        self._clock = clock
        self._entries: OrderedDict[str, _Entry[T]] = OrderedDict()
        self._guard = threading.Lock()

    def __len__(self) -> int:
        with self._guard:
            return len(self._entries)

    def set(self, session_id: str, value: T) -> None:
        with self._guard:
            self._prune_expired()
            self._entries.pop(session_id, None)
            while len(self._entries) >= self._max_sessions:
                self._entries.popitem(last=False)
            self._entries[session_id] = _Entry(value, self._clock() + self._ttl_s)

    def get(self, session_id: str) -> T | None:
        entry = self._touch(session_id)
        return entry.value if entry else None

    def lock(self, session_id: str) -> threading.Lock | None:
        entry = self._touch(session_id)
        return entry.lock if entry else None

    def _touch(self, session_id: str) -> _Entry[T] | None:
        with self._guard:
            entry = self._entries.get(session_id)
            if entry is None:
                return None
            now = self._clock()
            if entry.expires_at <= now:
                del self._entries[session_id]
                return None
            entry.expires_at = now + self._ttl_s
            self._entries.move_to_end(session_id)
            return entry

    def _prune_expired(self) -> None:
        now = self._clock()
        expired = [sid for sid, entry in self._entries.items() if entry.expires_at <= now]
        for sid in expired:
            del self._entries[sid]
