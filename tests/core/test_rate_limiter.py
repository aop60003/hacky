"""Tests for DynamicRateLimiter."""

from __future__ import annotations
import asyncio
import pytest

from vibee_hacker.core.rate_limiter import DynamicRateLimiter, RateLimiterStats


class TestRateLimiterInit:
    def test_init_defaults(self):
        rl = DynamicRateLimiter()
        assert rl.current_delay_ms == 0
        assert rl.stats.total_requests == 0
        assert rl.stats.throttled_count == 0
        assert rl.stats.error_count == 0

    def test_init_with_custom_values(self):
        rl = DynamicRateLimiter(initial_delay_ms=100, min_delay_ms=50, max_delay_ms=3000, backoff_factor=3.0)
        assert rl.current_delay_ms == 100
        assert rl._min_delay == 50
        assert rl._max_delay == 3000
        assert rl._backoff_factor == 3.0


class TestAcquire:
    def test_acquire_no_delay(self):
        """acquire() with 0 delay should complete instantly and increment total_requests."""
        rl = DynamicRateLimiter(initial_delay_ms=0)
        asyncio.get_event_loop().run_until_complete(rl.acquire())
        assert rl.stats.total_requests == 1

    def test_acquire_increments_total_requests(self):
        rl = DynamicRateLimiter(initial_delay_ms=0)
        loop = asyncio.new_event_loop()
        loop.run_until_complete(rl.acquire())
        loop.run_until_complete(rl.acquire())
        loop.run_until_complete(rl.acquire())
        loop.close()
        assert rl.stats.total_requests == 3


class TestReportSuccess:
    def test_report_success_tracks_avg_response(self):
        rl = DynamicRateLimiter()
        rl.report_success(100.0)
        rl.report_success(200.0)
        assert rl.stats.avg_response_ms == 150.0

    def test_report_success_reduces_delay_after_5(self):
        """Delay should reduce after 5+ successful responses."""
        rl = DynamicRateLimiter(initial_delay_ms=500)
        for _ in range(5):
            rl.report_success(50.0)
        assert rl.current_delay_ms < 500

    def test_report_success_respects_min_delay(self):
        """Delay should not go below min_delay_ms."""
        rl = DynamicRateLimiter(initial_delay_ms=100, min_delay_ms=80)
        for _ in range(50):
            rl.report_success(10.0)
        assert rl.current_delay_ms >= 80

    def test_report_success_trims_history_over_100(self):
        """Response time history should be capped."""
        rl = DynamicRateLimiter(initial_delay_ms=1000)
        for i in range(120):
            rl.report_success(float(i))
        assert len(rl._response_times) <= 100


class TestReportThrottled:
    def test_report_throttled_increases_delay(self):
        rl = DynamicRateLimiter(initial_delay_ms=0)
        rl.report_throttled()
        assert rl.current_delay_ms >= 100

    def test_report_throttled_increments_count(self):
        rl = DynamicRateLimiter()
        rl.report_throttled()
        rl.report_throttled()
        assert rl.stats.throttled_count == 2

    def test_report_throttled_uses_retry_after(self):
        """retry_after_ms should directly set the delay."""
        rl = DynamicRateLimiter(initial_delay_ms=0)
        rl.report_throttled(retry_after_ms=2000)
        assert rl.current_delay_ms == 2000

    def test_report_throttled_applies_backoff_factor(self):
        rl = DynamicRateLimiter(initial_delay_ms=200, backoff_factor=2.0)
        rl.report_throttled()
        assert rl.current_delay_ms == 400

    def test_report_throttled_backoff_factor_custom(self):
        rl = DynamicRateLimiter(initial_delay_ms=200, backoff_factor=3.0)
        rl.report_throttled()
        assert rl.current_delay_ms == 600


class TestReportError:
    def test_report_error_increases_delay(self):
        rl = DynamicRateLimiter(initial_delay_ms=0)
        rl.report_error()
        assert rl.current_delay_ms >= 50

    def test_report_error_increments_count(self):
        rl = DynamicRateLimiter()
        rl.report_error()
        rl.report_error()
        assert rl.stats.error_count == 2

    def test_report_error_multiplies_delay(self):
        rl = DynamicRateLimiter(initial_delay_ms=200)
        rl.report_error()
        assert rl.current_delay_ms == 300  # 200 * 1.5


class TestMaxDelayCap:
    def test_max_delay_cap_throttled(self):
        rl = DynamicRateLimiter(initial_delay_ms=4000, max_delay_ms=5000, backoff_factor=2.0)
        rl.report_throttled()
        assert rl.current_delay_ms <= 5000

    def test_max_delay_cap_error(self):
        rl = DynamicRateLimiter(initial_delay_ms=4000, max_delay_ms=5000)
        rl.report_error()
        assert rl.current_delay_ms <= 5000

    def test_max_delay_cap_retry_after(self):
        rl = DynamicRateLimiter(max_delay_ms=5000)
        rl.report_throttled(retry_after_ms=9999)
        assert rl.current_delay_ms <= 5000


class TestMinDelayFloor:
    def test_min_delay_floor_on_success(self):
        rl = DynamicRateLimiter(initial_delay_ms=200, min_delay_ms=100)
        for _ in range(100):
            rl.report_success(10.0)
        assert rl.current_delay_ms >= 100

    def test_min_delay_zero_allows_no_delay(self):
        rl = DynamicRateLimiter(initial_delay_ms=500, min_delay_ms=0)
        for _ in range(200):
            rl.report_success(10.0)
        assert rl.current_delay_ms >= 0


class TestStatsTracking:
    def test_stats_tracking_all_fields(self):
        rl = DynamicRateLimiter(initial_delay_ms=0)
        asyncio.get_event_loop().run_until_complete(rl.acquire())
        rl.report_success(120.0)
        rl.report_throttled()
        rl.report_error()
        s = rl.stats
        assert s.total_requests == 1
        assert s.throttled_count == 1
        assert s.error_count == 1
        assert s.avg_response_ms == 120.0
        assert s.current_delay_ms == rl.current_delay_ms

    def test_stats_is_same_object(self):
        rl = DynamicRateLimiter()
        s1 = rl.stats
        s2 = rl.stats
        assert s1 is s2
