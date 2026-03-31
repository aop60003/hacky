# tests/plugins/blackbox/test_cookie_security.py
"""Tests for cookie security flags check plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.cookie_security import CookieSecurityPlugin
from vibee_hacker.core.models import Target, Severity


class TestCookieSecurity:
    @pytest.fixture
    def plugin(self):
        return CookieSecurityPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com")

    @pytest.mark.asyncio
    async def test_cookie_missing_httponly_and_secure(self, plugin, target, httpx_mock):
        """Cookie lacking HttpOnly and Secure flags is reported."""
        httpx_mock.add_response(
            url="https://example.com",
            headers={"Set-Cookie": "session=abc123; Path=/"},
        )
        results = await plugin.run(target)
        rule_ids = [r.rule_id for r in results]
        assert any("httponly" in rid for rid in rule_ids)
        assert any("secure" in rid for rid in rule_ids)

    @pytest.mark.asyncio
    async def test_all_flags_set_no_results(self, plugin, target, httpx_mock):
        """Cookie with all recommended flags set → no results."""
        httpx_mock.add_response(
            url="https://example.com",
            headers={"Set-Cookie": "session=abc123; Path=/; HttpOnly; Secure; SameSite=Strict"},
        )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_no_cookies(self, plugin, target, httpx_mock):
        """Response with no Set-Cookie headers → no results."""
        httpx_mock.add_response(
            url="https://example.com",
            headers={"Content-Type": "text/html"},
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
    async def test_samesite_none_without_secure_reported(self, plugin, target, httpx_mock):
        """SameSite=None without Secure flag is reported."""
        httpx_mock.add_response(
            url="https://example.com",
            headers={"Set-Cookie": "session=abc123; Path=/; HttpOnly; SameSite=None"},
        )
        results = await plugin.run(target)
        rule_ids = [r.rule_id for r in results]
        assert any("samesite_none" in rid for rid in rule_ids)
