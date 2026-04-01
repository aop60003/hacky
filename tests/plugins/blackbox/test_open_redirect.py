# tests/plugins/blackbox/test_open_redirect.py
"""Tests for open redirect detection plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.open_redirect import OpenRedirectPlugin, REDIRECT_PATHS, REDIRECT_PARAMS
from vibee_hacker.core.models import Target, Severity, InterPhaseContext


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
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_redirect_blocked(self, plugin, httpx_mock):
        """200 response (no redirect to evil.com) returns no results."""
        target = Target(url="https://example.com/go?redirect=https://safe.com")
        httpx_mock.add_response(
            status_code=200,
            text="<html>Redirect blocked</html>",
            is_reusable=True,
        )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_no_redirect_params(self, plugin, httpx_mock):
        """URL without redirect params still probes common paths but finds nothing."""
        target = Target(url="https://example.com/page?q=test")
        httpx_mock.add_response(
            status_code=200,
            text="<html>Safe page</html>",
            is_reusable=True,
        )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False, assert_all_responses_were_requested=False)
    async def test_redirect_detected_on_common_path(self, plugin, httpx_mock):
        """302 on a common redirect path (e.g. /redirect?url=evil.com) is detected."""
        # Build a target that has no redirect params so the URL-based probing runs
        target = Target(url="https://example.com/")
        # Register the specific 302 redirect first so it takes priority over the catch-all
        httpx_mock.add_response(
            url="https://example.com/redirect?url=https://evil.com",
            status_code=302,
            headers={"location": "https://evil.com"},
            text="",
        )
        # Catch-all: all other probes return 200 (no redirect)
        httpx_mock.add_response(
            status_code=200,
            text="<html>OK</html>",
            is_reusable=True,
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].rule_id == "open_redirect"
        assert results[0].base_severity == Severity.MEDIUM
