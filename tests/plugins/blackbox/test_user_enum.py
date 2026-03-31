# tests/plugins/blackbox/test_user_enum.py
"""Tests for user enumeration detection plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.user_enum import UserEnumPlugin, LOGIN_PATHS
from vibee_hacker.core.models import Target, Severity


class TestUserEnum:
    @pytest.fixture
    def plugin(self):
        return UserEnumPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/")

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_responses_were_requested=False)
    async def test_different_response_for_valid_vs_invalid(self, plugin, target, httpx_mock):
        """Different response bodies for known vs unknown username is reported as MEDIUM.

        Only /login is mocked with differing responses; remaining paths return 404.
        Plugin stops at first finding, so not all mocks will be consumed.
        """
        # /login: known user returns different message than unknown
        httpx_mock.add_response(
            url="https://example.com/login",
            status_code=401,
            json={"error": "Invalid password"},
        )
        httpx_mock.add_response(
            url="https://example.com/login",
            status_code=401,
            json={"error": "User not found"},
        )
        # Remaining paths return 404 so they are skipped
        for path in LOGIN_PATHS[1:]:
            httpx_mock.add_response(
                url=f"https://example.com{path}",
                status_code=404,
                text="Not Found",
            )
            httpx_mock.add_response(
                url=f"https://example.com{path}",
                status_code=404,
                text="Not Found",
            )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.MEDIUM
        assert results[0].rule_id == "user_enumeration"
        assert results[0].cwe_id == "CWE-204"

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_responses_were_requested=False)
    async def test_same_response_no_finding(self, plugin, target, httpx_mock):
        """Identical responses for both usernames produce no results."""
        same_body = {"error": "Invalid credentials"}
        # Register a large pool of identical responses for all paths × 2 users
        for _ in range(len(LOGIN_PATHS) * 2 + 10):
            httpx_mock.add_response(
                status_code=401,
                json=same_body,
            )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_responses_were_requested=False)
    async def test_no_login_endpoint_no_finding(self, plugin, target, httpx_mock):
        """All login endpoints returning 404 produces no results."""
        # Each path is probed twice (known + unknown user); register a generous pool
        for _ in range(len(LOGIN_PATHS) * 2 + 10):
            httpx_mock.add_response(status_code=404, text="Not Found")
        results = await plugin.run(target)
        assert len(results) == 0
