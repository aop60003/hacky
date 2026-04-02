"""Dynamic rate limiter that adjusts based on server behavior."""

from __future__ import annotations
import asyncio
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class RateLimiterStats:
    total_requests: int = 0
    throttled_count: int = 0
    error_count: int = 0
    current_delay_ms: float = 0
    avg_response_ms: float = 0


class DynamicRateLimiter:
    def __init__(
        self,
        initial_delay_ms: float = 0,
        min_delay_ms: float = 0,
        max_delay_ms: float = 5000,
        backoff_factor: float = 2.0,
    ):
        self._delay_ms = initial_delay_ms
        self._min_delay = min_delay_ms
        self._max_delay = max_delay_ms
        self._backoff_factor = backoff_factor
        self._stats = RateLimiterStats(current_delay_ms=initial_delay_ms)
        self._response_times: list[float] = []
        self._lock = asyncio.Lock()

    async def acquire(self):
        """Wait before sending next request."""
        if self._delay_ms > 0:
            await asyncio.sleep(self._delay_ms / 1000)
        self._stats.total_requests += 1

    def report_success(self, response_time_ms: float):
        """Report a successful response. May decrease delay."""
        self._response_times.append(response_time_ms)
        if len(self._response_times) > 100:
            self._response_times = self._response_times[-50:]
        self._stats.avg_response_ms = sum(self._response_times) / len(self._response_times)
        # Gradually reduce delay on consistent success
        if self._delay_ms > self._min_delay and len(self._response_times) >= 5:
            self._delay_ms = max(self._min_delay, self._delay_ms * 0.9)
        self._stats.current_delay_ms = self._delay_ms

    def report_throttled(self, retry_after_ms: float = 0):
        """Report a 429 Too Many Requests. Increase delay."""
        self._stats.throttled_count += 1
        if retry_after_ms > 0:
            self._delay_ms = min(self._max_delay, retry_after_ms)
        else:
            self._delay_ms = min(
                self._max_delay, max(100, self._delay_ms * self._backoff_factor)
            )
        self._stats.current_delay_ms = self._delay_ms
        logger.info("Rate limited. New delay: %.0fms", self._delay_ms)

    def report_error(self):
        """Report a connection error. Slight backoff."""
        self._stats.error_count += 1
        self._delay_ms = min(self._max_delay, max(50, self._delay_ms * 1.5))
        self._stats.current_delay_ms = self._delay_ms

    @property
    def stats(self) -> RateLimiterStats:
        return self._stats

    @property
    def current_delay_ms(self) -> float:
        return self._delay_ms
