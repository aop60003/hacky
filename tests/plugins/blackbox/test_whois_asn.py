# tests/plugins/blackbox/test_whois_asn.py
"""Tests for WHOIS/ASN info collection plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.whois_asn import WhoisAsnPlugin
from vibee_hacker.core.models import Target, Severity


class TestWhoisAsn:
    @pytest.fixture
    def plugin(self):
        return WhoisAsnPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com")

    @pytest.mark.asyncio
    async def test_info_collected_from_server_header(self, plugin, target, httpx_mock):
        """Server header present leads to info collected result."""
        httpx_mock.add_response(
            url="https://example.com",
            status_code=200,
            headers={"Server": "nginx/1.18.0"},
            text="Hello",
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].rule_id == "whois_info_collected"
        assert results[0].base_severity == Severity.INFO

    @pytest.mark.asyncio
    async def test_no_url_returns_empty(self, plugin, httpx_mock):
        """No URL skips and returns empty."""
        target = Target(url=None)
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, target, httpx_mock):
        """Transport error returns empty results gracefully."""
        httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_no_server_header_still_reports(self, plugin, target, httpx_mock):
        """Even with no Server header, basic info is still collected."""
        httpx_mock.add_response(
            url="https://example.com",
            status_code=200,
            headers={},
            text="Hello",
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].rule_id == "whois_info_collected"
