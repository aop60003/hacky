# tests/plugins/blackbox/test_web_cache_deception.py
"""Tests for Web Cache Deception detection plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.web_cache_deception import WebCacheDeceptionPlugin
from vibee_hacker.core.models import Target, Severity


class TestWebCacheDeception:
    @pytest.fixture
    def plugin(self):
        return WebCacheDeceptionPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/profile")

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_cache_hit_on_decorated_url_is_vulnerable(self, plugin, target, httpx_mock):
        """Decorated URL returns cached content — reported as HIGH."""
        profile_body = "<html><h1>Welcome Alice</h1><p>Balance: $1000</p></html>"
        # Baseline response
        httpx_mock.add_response(
            url="https://example.com/profile",
            status_code=200,
            text=profile_body,
        )
        # Decorated URL with cache HIT
        httpx_mock.add_response(
            url="https://example.com/profile/nonexistent.css",
            status_code=200,
            text=profile_body,
            headers={"X-Cache": "HIT", "Content-Type": "text/html"},
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].rule_id == "web_cache_deception"
        assert results[0].cwe_id == "CWE-525"
        assert results[0].base_severity == Severity.HIGH

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_no_cache_hit_not_vulnerable(self, plugin, target, httpx_mock):
        """Decorated URL has no cache HIT header — no results."""
        profile_body = "<html><h1>Profile</h1></html>"
        httpx_mock.add_response(
            url="https://example.com/profile",
            status_code=200,
            text=profile_body,
        )
        # All decorated responses — no cache headers
        httpx_mock.add_response(
            status_code=200,
            text=profile_body,
            is_reusable=True,
        )
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_baseline_404_not_vulnerable(self, plugin, target, httpx_mock):
        """Baseline returns 404 — plugin skips, returns empty."""
        httpx_mock.add_response(
            url="https://example.com/profile",
            status_code=404,
            text="Not Found",
        )
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, httpx_mock):
        """TransportError on baseline request returns empty list."""
        target = Target(url="https://down.example.com/profile")
        httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        assert results == []
