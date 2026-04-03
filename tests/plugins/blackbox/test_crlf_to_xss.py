# tests/plugins/blackbox/test_crlf_to_xss.py
"""Tests for CRLF Header Injection to XSS detection plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.crlf_to_xss import CrlfToXssPlugin, DETECTION_COOKIE_MARKER
from vibee_hacker.core.models import Target, Severity


class TestCrlfToXss:
    @pytest.fixture
    def plugin(self):
        return CrlfToXssPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/redirect?next=home")

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_injected_set_cookie_header_is_vulnerable(self, plugin, target, httpx_mock):
        """Server emits injected Set-Cookie with our marker — reported as HIGH."""
        httpx_mock.add_response(
            status_code=200,
            text="Redirecting...",
            headers={"Set-Cookie": f"{DETECTION_COOKIE_MARKER}=injected; Path=/"},
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].rule_id == "crlf_header_injection"
        assert results[0].cwe_id == "CWE-113"
        assert results[0].base_severity == Severity.HIGH

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_injected_custom_header_is_vulnerable(self, plugin, target, httpx_mock):
        """Server emits X-XSS-Injected header — reported as HIGH."""
        httpx_mock.add_response(
            status_code=200,
            text="Redirecting...",
            headers={"X-XSS-Injected": "1"},
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].rule_id == "crlf_header_injection"

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_no_injected_headers_not_vulnerable(self, plugin, target, httpx_mock):
        """No injected headers in response — no results."""
        httpx_mock.add_response(
            status_code=200,
            text="<html>Normal page</html>",
            headers={"Content-Type": "text/html"},
            is_reusable=True,
        )
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_no_url_returns_empty(self, plugin):
        """Target without URL returns empty."""
        results = await plugin.run(Target(url=None, path="/some/path", mode="whitebox"))
        assert results == []

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, httpx_mock):
        """TransportError returns empty list."""
        target = Target(url="https://down.example.com/redirect?next=home")
        httpx_mock.add_exception(httpx.ConnectError("connection refused"), is_reusable=True)
        results = await plugin.run(target)
        assert results == []
