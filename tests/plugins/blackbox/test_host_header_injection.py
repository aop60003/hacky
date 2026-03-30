# tests/plugins/blackbox/test_host_header_injection.py
"""Tests for host header injection plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.host_header_injection import HostHeaderInjectionPlugin
from vibee_hacker.core.models import Target, Severity


class TestHostHeaderInjection:
    @pytest.fixture
    def plugin(self):
        return HostHeaderInjectionPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/")

    @pytest.mark.asyncio
    async def test_evil_com_reflected_in_response(self, plugin, target, httpx_mock):
        """evil.com reflected in response body is reported as HIGH."""
        httpx_mock.add_response(
            url="https://example.com/",
            status_code=200,
            text='<html><head><link rel="stylesheet" href="https://evil.com/style.css"></head></html>',
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.HIGH
        assert results[0].rule_id == "host_header_reflected"
        assert results[0].cwe_id == "CWE-644"

    @pytest.mark.asyncio
    async def test_not_reflected(self, plugin, target, httpx_mock):
        """Response not containing evil.com produces no results."""
        httpx_mock.add_response(
            url="https://example.com/",
            status_code=200,
            text="<html><body>Normal page without any injection</body></html>",
        )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, target, httpx_mock):
        """Transport error returns empty results gracefully."""
        httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        assert results == []
