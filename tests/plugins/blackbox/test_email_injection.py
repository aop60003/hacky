# tests/plugins/blackbox/test_email_injection.py
"""Tests for Email Header Injection detection plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.email_injection import EmailInjectionPlugin
from vibee_hacker.core.models import Target, Severity, InterPhaseContext


class TestEmailInjection:
    @pytest.fixture
    def plugin(self):
        return EmailInjectionPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/contact")

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_success_response_after_crlf_payload_is_vulnerable(
        self, plugin, target, httpx_mock
    ):
        """Server returns success after CRLF email payload — reported as HIGH."""
        httpx_mock.add_response(
            status_code=200,
            text="<html>Thank you! Your message has been sent.</html>",
            is_reusable=True,
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].rule_id == "email_header_injection"
        assert results[0].cwe_id == "CWE-93"
        assert results[0].base_severity == Severity.HIGH

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_redirect_after_payload_is_vulnerable(self, plugin, target, httpx_mock):
        """Server redirects (302) after CRLF payload — reported as HIGH."""
        httpx_mock.add_response(
            status_code=302,
            headers={"Location": "/contact?success=1"},
            text="",
            is_reusable=True,
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].rule_id == "email_header_injection"

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_validation_error_not_vulnerable(self, plugin, target, httpx_mock):
        """Server returns validation error — not vulnerable."""
        httpx_mock.add_response(
            status_code=200,
            text="<html>Error: Please enter a valid email address.</html>",
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
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_transport_error_returns_empty(self, plugin, httpx_mock):
        """TransportError returns empty list."""
        target = Target(url="https://down.example.com/contact")
        httpx_mock.add_exception(httpx.ConnectError("connection refused"), is_reusable=True)
        results = await plugin.run(target)
        assert results == []
