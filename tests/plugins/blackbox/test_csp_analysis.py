# tests/plugins/blackbox/test_csp_analysis.py
"""Tests for CSP analysis plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.csp_analysis import CspAnalysisPlugin
from vibee_hacker.core.models import Target, Severity


class TestCspAnalysis:
    @pytest.fixture
    def plugin(self):
        return CspAnalysisPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com")

    @pytest.mark.asyncio
    async def test_unsafe_inline_in_csp(self, plugin, target, httpx_mock):
        """unsafe-inline in script-src is reported."""
        httpx_mock.add_response(
            url="https://example.com",
            headers={"Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'"},
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        rule_ids = [r.rule_id for r in results]
        assert any("unsafe_inline" in rid for rid in rule_ids)

    @pytest.mark.asyncio
    async def test_strict_csp_no_results(self, plugin, target, httpx_mock):
        """Strict CSP with no unsafe directives produces no results."""
        httpx_mock.add_response(
            url="https://example.com",
            headers={"Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'"},
        )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_no_csp_header(self, plugin, target, httpx_mock):
        """Missing CSP header is reported."""
        httpx_mock.add_response(
            url="https://example.com",
            headers={},
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        rule_ids = [r.rule_id for r in results]
        assert any("missing" in rid for rid in rule_ids)

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, target, httpx_mock):
        """Transport error returns empty results gracefully."""
        httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        assert results == []
