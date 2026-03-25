"""Shared queue for storing detected endpoints during live mode."""

import threading
from typing import Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass(order=True)
class QueuedEndpoint:
    """An endpoint in the queue with priority based on score."""

    score: int = field(compare=True)
    endpoint: str = field(compare=False)
    normalized: str = field(compare=False)
    url: str = field(compare=False)
    method: str = field(compare=False)
    headers: dict = field(compare=False)
    timestamp: datetime = field(compare=False, default_factory=datetime.now)
    processed: bool = field(compare=False, default=False)


class EndpointQueue:
    """
    Thread-safe queue for storing detected endpoints.

    Features:
    - Avoid duplicates (by normalized endpoint)
    - Keep top scored endpoints
    - Track processed status
    - Maximum size limit
    """

    def __init__(self, max_size: int = 100, min_score: int = 5):
        self._queue = []
        self._seen_normalized = set()
        self._lock = threading.Lock()
        self.max_size = max_size
        self.min_score = min_score

    def add(
        self,
        endpoint: str,
        normalized: str,
        url: str,
        method: str = "GET",
        headers: dict = None,
        score: int = 0,
    ) -> bool:
        """
        Add endpoint to queue if not duplicate and above threshold.

        Args:
            endpoint: Original endpoint path
            normalized: Normalized endpoint (with {id})
            url: Full URL
            method: HTTP method
            headers: Request headers
            score: Priority score

        Returns:
            True if added, False if skipped
        """
        if headers is None:
            headers = {}

        with self._lock:
            if normalized in self._seen_normalized:
                return False

            if score < self.min_score:
                return False

            self._seen_normalized.add(normalized)

            queued = QueuedEndpoint(
                score=score,
                endpoint=endpoint,
                normalized=normalized,
                url=url,
                method=method,
                headers=headers,
            )

            self._queue.append(queued)
            self._queue.sort(reverse=True)

            if len(self._queue) > self.max_size:
                removed = self._queue.pop()
                self._seen_normalized.discard(removed.normalized)

            return True

    def get_top(self, limit: int = 1) -> list[QueuedEndpoint]:
        """Get highest scoring endpoint(s)."""
        with self._lock:
            return [e for e in self._queue[:limit] if not e.processed]

    def get_all(self) -> list[QueuedEndpoint]:
        """Get all queued endpoints."""
        with self._lock:
            return self._queue.copy()

    def get_unprocessed(self) -> list[QueuedEndpoint]:
        """Get all unprocessed endpoints."""
        with self._lock:
            return [e for e in self._queue if not e.processed]

    def mark_processed(self, normalized: str):
        """Mark an endpoint as processed."""
        with self._lock:
            for e in self._queue:
                if e.normalized == normalized:
                    e.processed = True
                    break

    def mark_all_processed(self):
        """Mark all endpoints as processed."""
        with self._lock:
            for e in self._queue:
                e.processed = True

    def clear(self):
        """Clear the queue."""
        with self._lock:
            self._queue.clear()
            self._seen_normalized.clear()

    def count(self) -> int:
        """Get count of queued items."""
        with self._lock:
            return len(self._queue)

    def count_unprocessed(self) -> int:
        """Get count of unprocessed items."""
        with self._lock:
            return sum(1 for e in self._queue if not e.processed)

    def has_new(self) -> bool:
        """Check if there are unprocessed endpoints."""
        with self._lock:
            return any(not e.processed for e in self._queue)


_global_queue = None


def get_queue() -> EndpointQueue:
    """Get or create the global queue instance."""
    global _global_queue
    if _global_queue is None:
        _global_queue = EndpointQueue()
    return _global_queue


def reset_queue():
    """Reset the global queue."""
    global _global_queue
    _global_queue = None
