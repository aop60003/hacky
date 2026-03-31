# tests/plugins/blackbox/test_security_txt_check.py
"""Tests for security.txt check plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.security_txt_check import SecurityTxtCheckPlugin
from vibee_hacker.core.models import Target, Severity


class TestSecurityTxtCheck:
    @pytest.fixture
    def plugin(self):
        return SecurityTxtCheckPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com")

    @pytest.mark.asyncio
    async def test_security_txt_missing_404(self, plugin, target, httpx_mock):
        """Missing security.txt (404) is reported as INFO."""
        httpx_mock.add_response(
            url="https://example.com/.well-known/security.txt",
            status_code=404,
            text="Not Found",
        )
        results = await plugin.run(target)
        assert len(results) == 1
        assert results[0].rule_id == "security_txt_missing"
        assert results[0].base_severity == Severity.INFO

    @pytest.mark.asyncio
    async def test_security_txt_present_with_contact(self, plugin, target, httpx_mock):
        """security.txt with Contact field → no vulnerability."""
        httpx_mock.add_response(
            url="https://example.com/.well-known/security.txt",
            status_code=200,
            text="Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00Z\n",
        )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, target, httpx_mock):
        """Transport error returns empty results gracefully."""
        httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        assert results == []
