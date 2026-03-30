# tests/plugins/blackbox/test_debug_detection.py
"""Tests for debug endpoint detection plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.debug_detection import DebugDetectionPlugin
from vibee_hacker.core.models import Target, Severity


class TestDebugDetection:
    @pytest.fixture
    def plugin(self):
        return DebugDetectionPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/")

    @pytest.mark.asyncio
    async def test_debug_endpoint_with_traceback(self, plugin, target, httpx_mock):
        """Debug endpoint accessible with traceback is reported as HIGH."""
        # First debug endpoint returns debug page
        httpx_mock.add_response(
            url="https://example.com/debug",
            status_code=200,
            text="Traceback (most recent call last): File app.py line 42",
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.HIGH
        assert results[0].rule_id == "debug_endpoint_exposed"
        assert results[0].cwe_id == "CWE-489"

    @pytest.mark.asyncio
    async def test_all_endpoints_404(self, plugin, target, httpx_mock):
        """All debug endpoints returning 404 produce no results."""
        # One response per DEBUG_PATH (6 paths)
        for _ in range(6):
            httpx_mock.add_response(status_code=404, text="Not Found")
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, target, httpx_mock):
        """Transport error on all endpoints returns empty results gracefully."""
        # Plugin continues on TransportError per endpoint, so supply an error for each path
        for _ in range(6):
            httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        assert results == []
