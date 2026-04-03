# tests/plugins/blackbox/test_saml_check.py
"""Tests for SamlCheckPlugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.saml_check import SamlCheckPlugin
from vibee_hacker.core.models import Target, Severity


class TestSamlCheck:
    @pytest.fixture
    def plugin(self):
        return SamlCheckPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://sso.example.com/")

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_unsigned_saml_accepted_detected(self, plugin, target, httpx_mock):
        """SAML endpoint accepting unsigned response is flagged as HIGH."""
        # GET probe returns 200 (endpoint exists)
        httpx_mock.add_response(
            url="https://sso.example.com/saml/sso",
            status_code=200,
            text="<html><body>SAML SSO Login</body></html>",
        )
        # POST with unsigned SAMLResponse returns 302 (accepted, redirects to app)
        httpx_mock.add_response(
            status_code=302,
            headers={"Location": "https://app.example.com/dashboard"},
            text="",
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        r = next((r for r in results if r.rule_id == "saml_signature_bypass"), None)
        assert r is not None
        assert r.base_severity == Severity.HIGH
        assert r.cwe_id == "CWE-347"

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_saml_properly_validates_signature(self, plugin, target, httpx_mock):
        """SAML endpoint rejecting unsigned response produces no HIGH findings."""
        # GET probe returns 200
        httpx_mock.add_response(
            url="https://sso.example.com/saml/sso",
            status_code=200,
            text="<html><body>SAML SSO Login</body></html>",
        )
        # POST returns 400 with signature validation error
        httpx_mock.add_response(
            status_code=400,
            text="Bad request: invalid signature verification failed",
        )
        results = await plugin.run(target)
        high_findings = [r for r in results if r.rule_id == "saml_signature_bypass"]
        assert high_findings == []

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_transport_error_returns_empty(self, plugin, target, httpx_mock):
        """Transport errors return empty results."""
        httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        bypass_findings = [r for r in results if r.rule_id == "saml_signature_bypass"]
        assert bypass_findings == []
