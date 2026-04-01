# tests/plugins/blackbox/test_default_creds.py
"""Tests for default credentials detection plugin (P2-2)."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.default_creds import DefaultCredsPlugin
from vibee_hacker.core.models import Target, Severity, InterPhaseContext


class TestDefaultCreds:
    @pytest.fixture
    def plugin(self):
        return DefaultCredsPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com")

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False, assert_all_responses_were_requested=False)
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
                httpx_mock.add_response(url=full_url, status_code=404, text="Not Found",
                                        is_reusable=True)
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.CRITICAL
        assert results[0].rule_id == "default_credentials"
        assert results[0].cwe_id == "CWE-798"

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_all_logins_fail(self, plugin, target, httpx_mock):
        """All login attempts fail -> no results."""
        from vibee_hacker.plugins.blackbox.default_creds import DEFAULT_CREDS
        for cred in DEFAULT_CREDS:
            full_url = f"https://example.com{cred['url_pattern']}"
            # Endpoint accessible
            httpx_mock.add_response(url=full_url, status_code=200, text="Login page",
                                    is_reusable=True)
            # Login fails
            httpx_mock.add_response(
                url=full_url,
                status_code=200,
                text="Invalid username or password",
                is_reusable=True,
            )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
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

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_login_path_default_creds(self, plugin, target, httpx_mock):
        """/login path with default creds admin/admin succeeds -> CRITICAL result."""
        from vibee_hacker.plugins.blackbox.default_creds import DEFAULT_CREDS
        for cred in DEFAULT_CREDS:
            full_url = f"https://example.com{cred['url_pattern']}"
            if cred["url_pattern"] == "/login" and cred["password"] == "admin":
                # First /login entry: endpoint accessible + login succeeds
                httpx_mock.add_response(url=full_url, status_code=200, text="Login page")
                httpx_mock.add_response(
                    url=full_url,
                    status_code=200,
                    text="Welcome to dashboard! You are logged in.",
                )
                break
            else:
                httpx_mock.add_response(url=full_url, status_code=404, text="Not Found",
                                        is_reusable=True)
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.CRITICAL
        assert results[0].rule_id == "default_credentials"

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_crawled_form_default_creds(self, plugin, target, httpx_mock):
        """Default creds succeed on a crawled login form -> CRITICAL result."""
        context = InterPhaseContext(
            crawl_forms=[
                {
                    "action": "/auth/login",
                    "method": "post",
                    "fields": ["username", "password"],
                }
            ]
        )
        # All DEFAULT_CREDS endpoints return 404
        from vibee_hacker.plugins.blackbox.default_creds import DEFAULT_CREDS
        for cred in DEFAULT_CREDS:
            full_url = f"https://example.com{cred['url_pattern']}"
            httpx_mock.add_response(url=full_url, status_code=404, text="Not Found",
                                    is_reusable=True)
        # Crawled form login succeeds on first try (admin/admin)
        httpx_mock.add_response(
            url="https://example.com/auth/login",
            status_code=200,
            text="Welcome to dashboard! You are logged in.",
        )
        results = await plugin.run(target, context=context)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.CRITICAL
        assert results[0].rule_id == "default_credentials"
