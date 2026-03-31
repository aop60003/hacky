# tests/plugins/blackbox/test_http_methods.py
"""Tests for HTTP dangerous methods plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.http_methods import HttpMethodsPlugin
from vibee_hacker.core.models import Target, Severity


class TestHttpMethods:
    @pytest.fixture
    def plugin(self):
        return HttpMethodsPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com")

    @pytest.mark.asyncio
    async def test_trace_allowed_and_echoes_body(self, plugin, target, httpx_mock):
        """TRACE allowed in Allow header and body echoed → XST reported."""
        # OPTIONS response listing TRACE
        httpx_mock.add_response(
            method="OPTIONS",
            url="https://example.com",
            headers={"Allow": "GET, POST, HEAD, OPTIONS, TRACE"},
        )
        # TRACE response echoes back the request body
        httpx_mock.add_response(
            method="TRACE",
            url="https://example.com",
            text="TRACE / HTTP/1.1\r\nX-Hacker-Probe: vibee-check",
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        rule_ids = [r.rule_id for r in results]
        assert any("trace" in rid for rid in rule_ids)

    @pytest.mark.asyncio
    async def test_only_safe_methods(self, plugin, target, httpx_mock):
        """Only GET/POST/HEAD in Allow header → no results."""
        httpx_mock.add_response(
            method="OPTIONS",
            url="https://example.com",
            headers={"Allow": "GET, POST, HEAD, OPTIONS"},
        )
        # TRACE request should return 405
        httpx_mock.add_response(
            method="TRACE",
            url="https://example.com",
            status_code=405,
            text="Method Not Allowed",
        )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, target, httpx_mock):
        """Transport error returns empty results gracefully."""
        httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        assert results == []
