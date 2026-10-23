"""A small thread-safe sliding-window rate limiter.

It protects the ingestion endpoint and the decoy listener from accidental or
hostile flooding.  The limiter is per-process; deployments with multiple API
workers should also enforce limits at the reverse proxy, which the deployment
runbook documents.
"""

from __future__ import annotations

import threading
import time
from collections import deque


class SlidingWindowLimiter:
    def __init__(self, limit: int, window_seconds: float = 60.0, *, max_keys: int = 4096):
        self.limit = limit
        self.window = window_seconds
        self.max_keys = max_keys
        self._events: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str, cost: int = 1) -> tuple[bool, float]:
        """Return (allowed, retry_after_seconds)."""
        now = time.monotonic()
        cutoff = now - self.window
        with self._lock:
            bucket = self._events.get(key)
            if bucket is None:
                if len(self._events) >= self.max_keys:
                    self._prune(cutoff)
                if len(self._events) >= self.max_keys:
                    # Refuse new keys rather than evict active buckets, which
                    # would let an attacker bypass the limit by rotating keys.
                    return False, self.window
                bucket = self._events[key] = deque()
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) + cost > self.limit:
                retry_after = max(0.0, self.window - (now - bucket[0])) if bucket else self.window
                return False, round(retry_after, 2)
            for _ in range(max(1, cost)):
                bucket.append(now)
            return True, 0.0

    def reset(self) -> None:
        with self._lock:
            self._events.clear()

    def _prune(self, cutoff: float) -> None:
        for key in list(self._events):
            bucket = self._events[key]
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if not bucket:
                del self._events[key]
