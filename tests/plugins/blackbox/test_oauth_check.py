# tests/plugins/blackbox/test_oauth_check.py
"""Tests for OAuth misconfiguration check plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.oauth_check import OauthCheckPlugin
from vibee_hacker.core.models import Target, Severity


class TestOauthCheck:
    @pytest.fixture
    def plugin(self):
        return OauthCheckPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/oauth/authorize")

    @pytest.mark.asyncio
    async def test_redirect_uri_bypass_accepted(self, plugin, target, httpx_mock):
        """redirect_uri=evil.com redirected to evil.com means bypass."""
        # First request: redirect_uri probe -> bypass redirect
        httpx_mock.add_response(
            status_code=302,
            headers={"Location": "https://evil.com/callback?code=abc123"},
        )
        # Second request: state check -> also 200 so that test shows at least redirect bypass
        httpx_mock.add_response(
            status_code=200,
            text="Login required",
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        rule_ids = {r.rule_id for r in results}
        assert "oauth_redirect_bypass" in rule_ids
        matching = [r for r in results if r.rule_id == "oauth_redirect_bypass"]
        assert matching[0].base_severity == Severity.HIGH
        assert matching[0].cwe_id == "CWE-601"

    @pytest.mark.asyncio
    async def test_redirect_uri_properly_rejected(self, plugin, target, httpx_mock):
        """redirect_uri=evil.com returns 400 means properly validated."""
        # First request: redirect_uri probe -> rejected
        httpx_mock.add_response(
            status_code=400,
            text="Invalid redirect_uri",
        )
        # Second request: state check -> also 400
        httpx_mock.add_response(
            status_code=400,
            text="Bad request",
        )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_no_oauth_endpoint_skipped(self, plugin, httpx_mock):
        """Non-OAuth URL produces no results without making requests."""
        target = Target(url="https://example.com/products")
        results = await plugin.run(target)
        assert results == []
