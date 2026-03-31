# tests/plugins/blackbox/test_auth_check.py
"""Tests for session/auth management check plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.auth_check import AuthCheckPlugin
from vibee_hacker.core.models import Target, Severity


class TestAuthCheck:
    @pytest.fixture
    def plugin(self):
        return AuthCheckPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/login")

    @pytest.mark.asyncio
    async def test_session_cookie_does_not_rotate_reported(self, plugin, target, httpx_mock):
        """Same session cookie returned on second login triggers session_fixation finding."""
        # First login response sets session cookie
        httpx_mock.add_response(
            url="https://example.com/login",
            status_code=200,
            headers={"Set-Cookie": "sessionid=abc123; HttpOnly; Path=/"},
            text='{"success": true}',
        )
        # Second login response with same session cookie (no rotation)
        httpx_mock.add_response(
            url="https://example.com/login",
            status_code=200,
            headers={"Set-Cookie": "sessionid=abc123; HttpOnly; Path=/"},
            text='{"success": true}',
        )
        results = await plugin.run(target)
        rule_ids = [r.rule_id for r in results]
        assert "session_fixation" in rule_ids
        finding = next(r for r in results if r.rule_id == "session_fixation")
        assert finding.base_severity == Severity.HIGH
        assert finding.cwe_id == "CWE-384"

    @pytest.mark.asyncio
    async def test_session_properly_rotates_no_finding(self, plugin, target, httpx_mock):
        """Different session cookies on subsequent logins yields no session_fixation finding."""
        # First login
        httpx_mock.add_response(
            url="https://example.com/login",
            status_code=200,
            headers={"Set-Cookie": "sessionid=first111; HttpOnly; Path=/"},
            text='{"success": true}',
        )
        # Second login - different session token
        httpx_mock.add_response(
            url="https://example.com/login",
            status_code=200,
            headers={"Set-Cookie": "sessionid=second999; HttpOnly; Path=/"},
            text='{"success": true}',
        )
        results = await plugin.run(target)
        rule_ids = [r.rule_id for r in results]
        assert "session_fixation" not in rule_ids

    @pytest.mark.asyncio
    async def test_no_session_cookie_no_finding(self, plugin, target, httpx_mock):
        """No Set-Cookie header yields no session findings.

        The plugin makes two POST requests (first login, second login), so register
        two matching responses.
        """
        for _ in range(2):
            httpx_mock.add_response(
                url="https://example.com/login",
                status_code=200,
                headers={},
                text='{"success": true}',
            )
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_no_url_returns_empty(self, plugin, httpx_mock):
        """No URL returns empty."""
        target = Target(url=None)
        results = await plugin.run(target)
        assert results == []
