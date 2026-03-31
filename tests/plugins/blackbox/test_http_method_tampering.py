# tests/plugins/blackbox/test_http_method_tampering.py
"""Tests for HTTP method tampering (override) plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.http_method_tampering import HttpMethodTamperingPlugin
from vibee_hacker.core.models import Target, Severity


class TestHttpMethodTampering:
    @pytest.fixture
    def plugin(self):
        return HttpMethodTamperingPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/")

    @pytest.mark.asyncio
    async def test_method_override_changes_response(self, plugin, target, httpx_mock):
        """Override header causing different response body triggers finding."""
        # Normal POST returns generic response
        httpx_mock.add_response(
            url="https://example.com/",
            status_code=200,
            text="POST response",
        )
        # POST with X-HTTP-Method-Override: DELETE returns different response
        httpx_mock.add_response(
            url="https://example.com/",
            status_code=200,
            text="Resource deleted successfully",
        )
        # POST with X-Method-Override: PUT also different
        httpx_mock.add_response(
            url="https://example.com/",
            status_code=200,
            text="Resource updated",
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].rule_id == "http_method_override_accepted"
        assert results[0].base_severity == Severity.MEDIUM
        assert results[0].cwe_id == "CWE-16"

    @pytest.mark.asyncio
    async def test_override_ignored_no_finding(self, plugin, target, httpx_mock):
        """Override headers having no effect (same response) yields no results."""
        same_text = "POST response - method override ignored"
        # Normal POST
        httpx_mock.add_response(
            url="https://example.com/",
            status_code=200,
            text=same_text,
        )
        # X-HTTP-Method-Override: DELETE - same response
        httpx_mock.add_response(
            url="https://example.com/",
            status_code=200,
            text=same_text,
        )
        # X-Method-Override: PUT - same response
        httpx_mock.add_response(
            url="https://example.com/",
            status_code=200,
            text=same_text,
        )
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, target, httpx_mock):
        """Transport error returns empty results gracefully."""
        httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_no_url_returns_empty(self, plugin, httpx_mock):
        """No URL skips and returns empty."""
        target = Target(url=None)
        results = await plugin.run(target)
        assert results == []
