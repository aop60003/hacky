# tests/plugins/blackbox/test_sri_check.py
"""Tests for Subresource Integrity (SRI) check plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.sri_check import SriCheckPlugin
from vibee_hacker.core.models import Target, Severity


class TestSriCheck:
    @pytest.fixture
    def plugin(self):
        return SriCheckPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com")

    @pytest.mark.asyncio
    async def test_external_script_without_integrity(self, plugin, target, httpx_mock):
        """External script without integrity attribute is reported."""
        httpx_mock.add_response(
            url="https://example.com",
            headers={"Content-Type": "text/html"},
            text='<html><head><script src="https://cdn.jsdelivr.net/npm/jquery/dist/jquery.min.js"></script></head></html>',
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].rule_id == "sri_missing"
        assert results[0].base_severity == Severity.MEDIUM
        assert results[0].cwe_id == "CWE-353"

    @pytest.mark.asyncio
    async def test_external_script_with_integrity(self, plugin, target, httpx_mock):
        """External script with integrity attribute → no results."""
        httpx_mock.add_response(
            url="https://example.com",
            headers={"Content-Type": "text/html"},
            text='<html><head><script src="https://cdn.jsdelivr.net/npm/jquery/dist/jquery.min.js" integrity="sha384-abc123" crossorigin="anonymous"></script></head></html>',
        )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_no_external_scripts(self, plugin, target, httpx_mock):
        """No external scripts → no results."""
        httpx_mock.add_response(
            url="https://example.com",
            headers={"Content-Type": "text/html"},
            text='<html><head><script src="/local/app.js"></script></head><body></body></html>',
        )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, target, httpx_mock):
        """Transport error returns empty results gracefully."""
        httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        assert results == []
