# tests/plugins/blackbox/test_cookie_security.py
"""Tests for cookie security flags check plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.cookie_security import CookieSecurityPlugin, COOKIE_PATHS
from vibee_hacker.core.models import Target, Severity, InterPhaseContext


class TestCookieSecurity:
    @pytest.fixture
    def plugin(self):
        return CookieSecurityPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com")

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
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
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_all_flags_set_no_results(self, plugin, target, httpx_mock):
        """Cookie with all recommended flags set → no results (probed paths return no cookies)."""
        httpx_mock.add_response(
            url="https://example.com",
            headers={"Set-Cookie": "session=abc123; Path=/; HttpOnly; Secure; SameSite=Strict"},
        )
        # Probed paths return no Set-Cookie headers
        for path in COOKIE_PATHS:
            httpx_mock.add_response(
                url=f"https://example.com{path}",
                headers={"Content-Type": "text/html"},
                status_code=200,
            )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_no_cookies(self, plugin, target, httpx_mock):
        """Response with no Set-Cookie headers → no results."""
        httpx_mock.add_response(
            url="https://example.com",
            headers={"Content-Type": "text/html"},
        )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_transport_error_returns_empty(self, plugin, target, httpx_mock):
        """Transport error on start URL returns empty results gracefully."""
        httpx_mock.add_exception(
            httpx.ConnectError("connection refused"), is_reusable=True
        )
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_samesite_none_without_secure_reported(self, plugin, target, httpx_mock):
        """SameSite=None without Secure flag is reported."""
        httpx_mock.add_response(
            url="https://example.com",
            headers={"Set-Cookie": "session=abc123; Path=/; HttpOnly; SameSite=None"},
        )
        results = await plugin.run(target)
        rule_ids = [r.rule_id for r in results]
        assert any("samesite_none" in rid for rid in rule_ids)

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_cookie_detected_on_login_path(self, plugin, httpx_mock):
        """Cookie without flags set on /login path is also detected."""
        target = Target(url="https://example.com/home")
        # Start URL returns no cookies
        httpx_mock.add_response(
            url="https://example.com/home",
            headers={"Content-Type": "text/html"},
        )
        # /login path sets an insecure cookie
        httpx_mock.add_response(
            url="https://example.com/login",
            headers={"Set-Cookie": "session=xyz; Path=/"},
            status_code=200,
        )
        results = await plugin.run(target)
        rule_ids = [r.rule_id for r in results]
        assert any("httponly" in rid for rid in rule_ids)
        assert any("secure" in rid for rid in rule_ids)

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_deduplication_across_paths(self, plugin, httpx_mock):
        """Same cookie name with same issue from multiple paths is reported only once."""
        target = Target(url="https://example.com")
        # Start URL sets insecure cookie
        httpx_mock.add_response(
            url="https://example.com",
            headers={"Set-Cookie": "session=abc; Path=/"},
        )
        # /login also sets the same insecure cookie
        httpx_mock.add_response(
            url="https://example.com/login",
            headers={"Set-Cookie": "session=abc; Path=/"},
            status_code=200,
        )
        results = await plugin.run(target)
        # Each unique (cookie_name, rule_id) should appear only once
        seen = set()
        for r in results:
            key = (r.title, r.rule_id)
            assert key not in seen, f"Duplicate result: {key}"
            seen.add(key)
