# tests/plugins/blackbox/test_broken_auth.py
"""Tests for broken authentication flow detection plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.broken_auth_flow import BrokenAuthPlugin
from vibee_hacker.core.models import Target, Severity


class TestBrokenAuth:
    @pytest.fixture
    def plugin(self):
        return BrokenAuthPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/api/profile")

    @pytest.mark.asyncio
    async def test_no_auth_returns_200_with_data(self, plugin, target, httpx_mock):
        """200 response with substantial body without auth is reported as CRITICAL."""
        body = '{"user": "admin", "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret", "role": "administrator", "data": "sensitive information here"}'
        httpx_mock.add_response(
            status_code=200,
            text=body,
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.CRITICAL
        assert results[0].rule_id == "broken_auth_no_token"
        assert results[0].cwe_id == "CWE-287"

    @pytest.mark.asyncio
    async def test_returns_401_properly(self, plugin, target, httpx_mock):
        """Proper 401 response returns no results (auth working correctly)."""
        httpx_mock.add_response(status_code=401, text='{"error": "Unauthorized"}')
        httpx_mock.add_response(status_code=401, text='{"error": "Unauthorized"}')
        httpx_mock.add_response(status_code=401, text='{"error": "Unauthorized"}')
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, target, httpx_mock):
        """Transport error returns empty results gracefully."""
        httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        assert results == []
