# tests/plugins/blackbox/test_email_security.py
"""Tests for email security plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.email_security import EmailSecurityPlugin
from vibee_hacker.core.models import Target, Severity


class TestEmailSecurity:
    @pytest.fixture
    def plugin(self):
        return EmailSecurityPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/")

    @pytest.mark.asyncio
    async def test_no_mta_sts_reported(self, plugin, target, httpx_mock):
        """No MTA-STS policy and no email security headers is reported as MEDIUM."""
        httpx_mock.add_response(
            url="https://example.com/",
            status_code=200,
            text="<html><body>Hello</body></html>",
            headers={},
        )
        httpx_mock.add_response(
            url="https://example.com/.well-known/mta-sts.txt",
            status_code=404,
            text="Not Found",
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        rule_ids = [r.rule_id for r in results]
        assert any("email_security" in rid for rid in rule_ids)
        assert all(r.cwe_id == "CWE-290" for r in results)

    @pytest.mark.asyncio
    async def test_mta_sts_present_no_finding(self, plugin, target, httpx_mock):
        """MTA-STS present with email headers produces no finding."""
        httpx_mock.add_response(
            url="https://example.com/",
            status_code=200,
            text="<html><body>Hello</body></html>",
            headers={
                "Authentication-Results": "mx.example.com; dkim=pass; spf=pass; dmarc=pass",
            },
        )
        httpx_mock.add_response(
            url="https://example.com/.well-known/mta-sts.txt",
            status_code=200,
            text="version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400",
        )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, target, httpx_mock):
        """Transport error on main page returns empty results gracefully."""
        # Only the main URL is fetched; if it errors, we return early
        httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        assert results == []
