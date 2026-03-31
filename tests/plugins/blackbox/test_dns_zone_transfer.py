# tests/plugins/blackbox/test_dns_zone_transfer.py
"""Tests for DNS zone transfer / DNS info exposure plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.dns_zone_transfer import DnsZoneTransferPlugin
from vibee_hacker.core.models import Target, Severity


class TestDnsZoneTransfer:
    @pytest.fixture
    def plugin(self):
        return DnsZoneTransferPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="http://example.com/")

    @pytest.mark.asyncio
    async def test_dns_info_in_response_is_reported(self, plugin, target, httpx_mock):
        """DNS NS/SOA record patterns in response body are reported as HIGH."""
        from vibee_hacker.plugins.blackbox.dns_zone_transfer import DNS_ADMIN_PATHS
        # First path returns DNS zone-like data
        httpx_mock.add_response(
            url=f"http://example.com{DNS_ADMIN_PATHS[0]}",
            status_code=200,
            text="NS record: ns1.example.com\nSOA example.com ns1.example.com\nIN A 1.2.3.4",
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.HIGH
        assert results[0].rule_id == "dns_zone_info_exposed"
        assert results[0].cwe_id == "CWE-200"

    @pytest.mark.asyncio
    async def test_no_dns_info_returns_empty(self, plugin, target, httpx_mock):
        """Normal pages with no DNS info produce no results."""
        from vibee_hacker.plugins.blackbox.dns_zone_transfer import DNS_ADMIN_PATHS
        for _ in range(len(DNS_ADMIN_PATHS)):
            httpx_mock.add_response(
                status_code=404,
                text="<html><body>Not Found</body></html>",
            )
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, target, httpx_mock):
        """Transport error is handled gracefully."""
        from vibee_hacker.plugins.blackbox.dns_zone_transfer import DNS_ADMIN_PATHS
        for _ in range(len(DNS_ADMIN_PATHS)):
            httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        assert results == []
