# tests/plugins/blackbox/test_rate_limit_check.py
"""Tests for rate limit absence detection plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.rate_limit_check import RateLimitCheckPlugin
from vibee_hacker.core.models import Target, Severity


class TestRateLimitCheck:
    @pytest.fixture
    def plugin(self):
        return RateLimitCheckPlugin()

    @pytest.fixture
    def auth_target(self):
        return Target(url="https://example.com/api/login")

    @pytest.mark.asyncio
    async def test_no_429_after_20_requests_is_vulnerable(self, plugin, auth_target, httpx_mock):
        """No 429 after 20 rapid requests to auth endpoint is reported as HIGH."""
        for _ in range(20):
            httpx_mock.add_response(
                url="https://example.com/api/login",
                status_code=200,
                text='{"error": "invalid credentials"}',
            )
        results = await plugin.run(auth_target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.HIGH
        assert results[0].rule_id == "rate_limit_absent"
        assert results[0].cwe_id == "CWE-770"

    @pytest.mark.asyncio
    async def test_429_received_not_vulnerable(self, plugin, auth_target, httpx_mock):
        """Receiving 429 response means rate limiting is active - no findings."""
        # First few requests succeed, then 429
        for _ in range(5):
            httpx_mock.add_response(
                url="https://example.com/api/login",
                status_code=200,
                text='{"error": "invalid credentials"}',
            )
        httpx_mock.add_response(
            url="https://example.com/api/login",
            status_code=429,
            text="Too Many Requests",
            headers={"Retry-After": "60"},
        )
        results = await plugin.run(auth_target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_non_auth_url_skipped(self, plugin, httpx_mock):
        """Non-auth URL is skipped entirely with no results."""
        target = Target(url="https://example.com/api/products")
        results = await plugin.run(target)
        assert results == []
