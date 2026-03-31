# tests/plugins/blackbox/test_server_info_leak.py
"""Tests for server information leak detection plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.server_info_leak import ServerInfoLeakPlugin
from vibee_hacker.core.models import Target, Severity


class TestServerInfoLeak:
    @pytest.fixture
    def plugin(self):
        return ServerInfoLeakPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com")

    @pytest.mark.asyncio
    async def test_server_header_with_version(self, plugin, target, httpx_mock):
        """Server header disclosing version is reported."""
        httpx_mock.add_response(
            url="https://example.com",
            headers={"Server": "Apache/2.4.51 (Unix)"},
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].rule_id == "server_info_header_leak"
        assert results[0].base_severity == Severity.LOW
        assert results[0].cwe_id == "CWE-200"

    @pytest.mark.asyncio
    async def test_no_info_headers(self, plugin, target, httpx_mock):
        """No info-leaking headers → no results."""
        httpx_mock.add_response(
            url="https://example.com",
            headers={"Content-Type": "text/html"},
            text="<html><body>Hello</body></html>",
        )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, target, httpx_mock):
        """Transport error returns empty results gracefully."""
        httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_html_comment_version_info(self, plugin, target, httpx_mock):
        """HTML comment disclosing version is reported."""
        httpx_mock.add_response(
            url="https://example.com",
            headers={"Content-Type": "text/html"},
            text="<html><!-- Version 1.2.3 --><body>Hello</body></html>",
        )
        results = await plugin.run(target)
        assert len(results) >= 1
