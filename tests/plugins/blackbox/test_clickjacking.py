# tests/plugins/blackbox/test_clickjacking.py
"""Tests for clickjacking detection plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.clickjacking import ClickjackingPlugin
from vibee_hacker.core.models import Target, Severity


class TestClickjacking:
    @pytest.fixture
    def plugin(self):
        return ClickjackingPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com")

    @pytest.mark.asyncio
    async def test_both_protections_missing(self, plugin, target, httpx_mock):
        """Both X-Frame-Options and frame-ancestors missing → vulnerability reported."""
        httpx_mock.add_response(
            url="https://example.com",
            headers={"Content-Security-Policy": "default-src 'self'"},
        )
        results = await plugin.run(target)
        assert len(results) == 1
        assert results[0].rule_id == "clickjacking_no_protection"
        assert results[0].base_severity == Severity.MEDIUM
        assert results[0].cwe_id == "CWE-1021"

    @pytest.mark.asyncio
    async def test_xfo_deny_present(self, plugin, target, httpx_mock):
        """X-Frame-Options: DENY present → no vulnerability."""
        httpx_mock.add_response(
            url="https://example.com",
            headers={"X-Frame-Options": "DENY"},
        )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_csp_frame_ancestors_present(self, plugin, target, httpx_mock):
        """CSP frame-ancestors directive present → no vulnerability."""
        httpx_mock.add_response(
            url="https://example.com",
            headers={"Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'"},
        )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, target, httpx_mock):
        """Transport error returns empty results gracefully."""
        httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        assert results == []
