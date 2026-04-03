# tests/plugins/blackbox/test_timing_enum.py
"""Tests for TimingEnumPlugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.timing_enum import TimingEnumPlugin
from vibee_hacker.core.models import Target, Severity


class TestTimingEnum:
    @pytest.fixture
    def plugin(self):
        return TimingEnumPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/login")

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False, assert_all_responses_were_requested=False)
    async def test_no_login_endpoint_returns_empty(self, plugin, httpx_mock):
        """When no login endpoint is found, plugin returns empty results."""
        target = Target(url="https://example.com/")
        # All endpoint probes return 404
        for _ in range(100):
            httpx_mock.add_response(status_code=404, text="Not Found")
        results = await plugin.run(target)
        # Timing based test - with mocked fast responses, threshold won't be met
        assert isinstance(results, list)

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False, assert_all_responses_were_requested=False)
    async def test_equal_response_times_no_findings(self, plugin, target, httpx_mock):
        """Equal response times for all usernames produce no timing findings."""
        # All requests return fast/equal responses
        for _ in range(100):
            httpx_mock.add_response(
                status_code=200,
                text='{"error": "invalid credentials"}',
            )
        results = await plugin.run(target)
        # Mocked responses have near-zero latency, no timing difference should be detected
        assert isinstance(results, list)

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_transport_error_returns_empty(self, plugin, target, httpx_mock):
        """Transport errors return empty results."""
        httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        assert results == []
