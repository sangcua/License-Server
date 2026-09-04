from __future__ import annotations

from collections import defaultdict, deque
import threading
import time


class MemoryRateLimiter:
    """Small per-process limiter suitable for the single-worker local deployment."""

    def __init__(self) -> None:
        self._buckets: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int, window_s: float = 60.0) -> bool:
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets[key]
            while bucket and now - bucket[0] >= window_s:
                bucket.popleft()
            if len(bucket) >= limit:
                return False
            bucket.append(now)
            return True

