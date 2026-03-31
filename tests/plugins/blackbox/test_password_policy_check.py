# tests/plugins/blackbox/test_password_policy_check.py
"""Tests for password policy check plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.password_policy_check import PasswordPolicyCheckPlugin
from vibee_hacker.core.models import Target, Severity


class TestPasswordPolicyCheck:
    @pytest.fixture
    def plugin(self):
        return PasswordPolicyCheckPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com")

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_responses_were_requested=False, assert_all_requests_were_expected=False)
    async def test_weak_password_accepted_reported(self, plugin, target, httpx_mock):
        """Signup endpoint accepting weak password (200) triggers finding.

        The plugin finds /register immediately and breaks from the inner loop, then
        continues to remaining paths. Those paths have no mock registered so we disable
        the strict matching assertions.
        """
        httpx_mock.add_response(
            url="https://example.com/register",
            status_code=200,
            text='{"success": true}',
        )
        # Remaining paths return 404 to keep the plugin from raising unexpected request errors
        for path in ["/signup", "/password/reset", "/change-password"]:
            httpx_mock.add_response(
                url=f"https://example.com{path}",
                status_code=404,
                text="Not Found",
            )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].rule_id == "password_policy_weak"
        assert results[0].base_severity == Severity.MEDIUM
        assert results[0].cwe_id == "CWE-521"

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_responses_were_requested=False)
    async def test_weak_password_rejected_no_finding(self, plugin, target, httpx_mock):
        """All endpoints rejecting weak password (400) yields no results.

        The exact number of requests depends on 4 paths x 3 passwords = 12 max,
        so register enough 400s and allow unused ones.
        """
        for _ in range(12):
            httpx_mock.add_response(
                status_code=400,
                text='{"error": "Password too weak"}',
            )
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_no_signup_endpoint_no_finding(self, plugin, httpx_mock):
        """Target with no URL returns empty."""
        target = Target(url=None)
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_responses_were_requested=False)
    async def test_transport_error_returns_empty(self, plugin, target, httpx_mock):
        """Transport errors are swallowed gracefully.

        Register 12 exceptions (4 paths x 3 passwords max). Allow unused ones.
        """
        for _ in range(12):
            httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        assert results == []
