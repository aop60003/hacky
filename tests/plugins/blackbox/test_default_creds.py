# tests/plugins/blackbox/test_default_creds.py
"""Tests for default credentials detection plugin (P2-2)."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.default_creds import DefaultCredsPlugin
from vibee_hacker.core.models import Target, Severity


class TestDefaultCreds:
    @pytest.fixture
    def plugin(self):
        return DefaultCredsPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com")

    @pytest.mark.asyncio
    async def test_admin_creds_succeed(self, plugin, target, httpx_mock):
        """admin/admin login succeeds -> CRITICAL result."""
        from vibee_hacker.plugins.blackbox.default_creds import DEFAULT_CREDS
        for cred in DEFAULT_CREDS:
            url_pattern = cred["url_pattern"]
            full_url = f"https://example.com{url_pattern}"
            if url_pattern == "/admin/":
                # Endpoint accessible
                httpx_mock.add_response(url=full_url, status_code=200, text="Admin login")
                # Login succeeds (no 'invalid' in response, has dashboard link)
                httpx_mock.add_response(
                    url=full_url,
                    status_code=200,
                    text="Welcome to dashboard! You are logged in.",
                )
            else:
                httpx_mock.add_response(url=full_url, status_code=404, text="Not Found")
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.CRITICAL
        assert results[0].rule_id == "default_credentials"
        assert results[0].cwe_id == "CWE-798"

    @pytest.mark.asyncio
    async def test_all_logins_fail(self, plugin, target, httpx_mock):
        """All login attempts fail -> no results."""
        from vibee_hacker.plugins.blackbox.default_creds import DEFAULT_CREDS
        for cred in DEFAULT_CREDS:
            full_url = f"https://example.com{cred['url_pattern']}"
            # Endpoint accessible
            httpx_mock.add_response(url=full_url, status_code=200, text="Login page")
            # Login fails
            httpx_mock.add_response(
                url=full_url,
                status_code=200,
                text="Invalid username or password",
            )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, httpx_mock):
        """TransportError on all requests returns empty list."""
        target = Target(url="https://down.example.com")
        httpx_mock.add_exception(
            httpx.ConnectError("connection refused"), is_reusable=True
        )
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_no_url_not_applicable(self, plugin):
        """Plugin without URL target is not applicable."""
        target = Target(path="/some/path", mode="whitebox")
        assert plugin.is_applicable(target) is False

    @pytest.mark.asyncio
    async def test_destructive_level(self, plugin):
        """Plugin destructive_level must be 2."""
        assert plugin.destructive_level == 2
