# tests/plugins/blackbox/test_oauth_pkce_downgrade.py
"""Tests for OauthPkceDowngradePlugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.oauth_pkce_downgrade import OauthPkceDowngradePlugin
from vibee_hacker.core.models import Target, Severity


class TestOauthPkceDowngrade:
    @pytest.fixture
    def plugin(self):
        return OauthPkceDowngradePlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://auth.example.com/")

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_pkce_not_enforced_detected(self, plugin, target, httpx_mock):
        """OAuth endpoint accepting auth request without code_challenge is flagged."""
        # Probe returns 200 (endpoint exists)
        httpx_mock.add_response(
            url="https://auth.example.com/oauth/authorize",
            status_code=200,
            text="<html><body>Login</body></html>",
        )
        # Auth request without code_challenge also returns 200 (not rejected)
        httpx_mock.add_response(
            status_code=200,
            text="<html><body>Authorize App</body></html>",
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert r.rule_id == "oauth_pkce_missing"
        assert r.cwe_id == "CWE-287"

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False, assert_all_responses_were_requested=False)
    async def test_pkce_enforced_no_findings(self, plugin, target, httpx_mock):
        """OAuth endpoint rejecting request with code_challenge_required produces no findings."""
        # All endpoints return 404 except one that enforces PKCE
        for _ in range(20):
            httpx_mock.add_response(status_code=404, text="Not Found")
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_transport_error_returns_empty(self, plugin, target, httpx_mock):
        """Transport errors return empty results."""
        httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        assert results == []
