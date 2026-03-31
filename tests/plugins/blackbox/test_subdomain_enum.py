# tests/plugins/blackbox/test_subdomain_enum.py
"""Tests for subdomain enumeration plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.subdomain_enum import SubdomainEnumPlugin, COMMON_SUBDOMAINS
from vibee_hacker.core.models import Target, Severity


class TestSubdomainEnum:
    @pytest.fixture
    def plugin(self):
        return SubdomainEnumPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="http://example.com")

    @pytest.mark.asyncio
    async def test_subdomain_responds_200_reported(self, plugin, target, httpx_mock):
        """api.example.com responding 200 is reported as discovered subdomain."""
        # Add 200 for api subdomain, 404 for all others
        for sub in COMMON_SUBDOMAINS:
            if sub == "api":
                httpx_mock.add_response(
                    url=f"http://{sub}.example.com/",
                    status_code=200,
                    text="API endpoint",
                )
            else:
                httpx_mock.add_response(
                    url=f"http://{sub}.example.com/",
                    status_code=404,
                    text="Not Found",
                )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].rule_id == "subdomain_discovered"
        assert results[0].base_severity == Severity.INFO
        assert "api.example.com" in results[0].description

    @pytest.mark.asyncio
    async def test_all_subdomains_fail_no_results(self, plugin, target, httpx_mock):
        """All subdomains returning 404 yields no results."""
        for sub in COMMON_SUBDOMAINS:
            httpx_mock.add_response(
                url=f"http://{sub}.example.com/",
                status_code=404,
                text="Not Found",
            )
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, target, httpx_mock):
        """Transport errors are swallowed and no results returned."""
        for sub in COMMON_SUBDOMAINS:
            httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_no_url_returns_empty(self, plugin, httpx_mock):
        """No URL returns empty results without making requests."""
        target = Target(url=None)
        results = await plugin.run(target)
        assert results == []
