# tests/plugins/blackbox/test_open_redirect.py
"""Tests for open redirect detection plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.open_redirect import OpenRedirectPlugin
from vibee_hacker.core.models import Target, Severity


class TestOpenRedirect:
    @pytest.fixture
    def plugin(self):
        return OpenRedirectPlugin()

    @pytest.mark.asyncio
    async def test_redirect_to_evil(self, plugin, httpx_mock):
        """302 redirect with Location pointing to evil.com is reported as MEDIUM."""
        target = Target(url="https://example.com/go?url=https://safe.com")
        httpx_mock.add_response(
            status_code=302,
            headers={"location": "https://evil.com"},
            text="",
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.MEDIUM
        assert results[0].rule_id == "open_redirect"
        assert results[0].cwe_id == "CWE-601"

    @pytest.mark.asyncio
    async def test_redirect_blocked(self, plugin, httpx_mock):
        """200 response (no redirect to evil.com) returns no results."""
        target = Target(url="https://example.com/go?redirect=https://safe.com")
        httpx_mock.add_response(
            status_code=200,
            text="<html>Redirect blocked</html>",
        )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_no_redirect_params(self, plugin, httpx_mock):
        """URL without redirect params returns no results."""
        target = Target(url="https://example.com/page?q=test")
        results = await plugin.run(target)
        assert len(results) == 0
