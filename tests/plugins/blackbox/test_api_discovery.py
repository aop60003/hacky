# tests/plugins/blackbox/test_api_discovery.py
"""Tests for API discovery plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.api_discovery import ApiDiscoveryPlugin
from vibee_hacker.core.models import Target, Severity


class TestApiDiscovery:
    @pytest.fixture
    def plugin(self):
        return ApiDiscoveryPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/")

    @pytest.mark.asyncio
    async def test_swagger_json_found(self, plugin, target, httpx_mock):
        """swagger.json returning 200 with JSON content is reported as INFO."""
        # First probe path is /swagger.json - return 200 with JSON
        httpx_mock.add_response(
            url="https://example.com/swagger.json",
            status_code=200,
            text='{"swagger": "2.0", "info": {"title": "Test API"}}',
            headers={"Content-Type": "application/json"},
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.INFO
        assert results[0].rule_id == "api_endpoint_discovered"
        assert results[0].cwe_id is None

    @pytest.mark.asyncio
    async def test_all_return_404(self, plugin, target, httpx_mock):
        """All probed paths returning 404 produce no results."""
        from vibee_hacker.plugins.blackbox.api_discovery import API_PATHS
        for _ in range(len(API_PATHS)):
            httpx_mock.add_response(status_code=404, text="Not Found")
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, target, httpx_mock):
        """Transport error on all endpoints returns empty results gracefully."""
        from vibee_hacker.plugins.blackbox.api_discovery import API_PATHS
        for _ in range(len(API_PATHS)):
            httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        assert results == []
