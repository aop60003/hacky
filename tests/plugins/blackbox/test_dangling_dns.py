# tests/plugins/blackbox/test_dangling_dns.py
"""Tests for dangling DNS / subdomain takeover signature detection plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.dangling_dns import DanglingDnsPlugin
from vibee_hacker.core.models import Target, Severity


class TestDanglingDns:
    @pytest.fixture
    def plugin(self):
        return DanglingDnsPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="http://sub.example.com/")

    @pytest.mark.asyncio
    async def test_github_pages_takeover_signature(self, plugin, target, httpx_mock):
        """GitHub Pages takeover signature in response body is reported as HIGH."""
        httpx_mock.add_response(
            url="http://sub.example.com/",
            status_code=404,
            text="There isn't a GitHub Pages site here.",
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.HIGH
        assert results[0].rule_id == "dangling_dns_takeover"
        assert results[0].cwe_id == "CWE-284"

    @pytest.mark.asyncio
    async def test_normal_response_returns_empty(self, plugin, target, httpx_mock):
        """Normal 200 response without takeover signatures produces no results."""
        httpx_mock.add_response(
            url="http://sub.example.com/",
            status_code=200,
            text="<html><body>Welcome to my site!</body></html>",
        )
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, target, httpx_mock):
        """Transport error is handled gracefully."""
        httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        assert results == []
