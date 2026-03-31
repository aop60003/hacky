# tests/plugins/blackbox/test_ssl_check.py
"""Tests for SSL/TLS configuration check plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.ssl_check import SslCheckPlugin
from vibee_hacker.core.models import Target, Severity


class TestSslCheck:
    @pytest.fixture
    def plugin(self):
        return SslCheckPlugin()

    @pytest.fixture
    def https_target(self):
        return Target(url="https://example.com")

    @pytest.mark.asyncio
    async def test_no_hsts_header_reported(self, plugin, https_target, httpx_mock):
        """HTTPS target missing HSTS header triggers ssl_no_hsts finding."""
        httpx_mock.add_response(
            url="https://example.com",
            status_code=200,
            headers={},
            text="Hello",
        )
        results = await plugin.run(https_target)
        rule_ids = [r.rule_id for r in results]
        assert "ssl_no_hsts" in rule_ids
        hsts_result = next(r for r in results if r.rule_id == "ssl_no_hsts")
        assert hsts_result.base_severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_hsts_good_max_age_no_finding(self, plugin, https_target, httpx_mock):
        """HSTS with max-age >= 31536000 yields no ssl_no_hsts finding."""
        httpx_mock.add_response(
            url="https://example.com",
            status_code=200,
            headers={"Strict-Transport-Security": "max-age=31536000; includeSubDomains"},
            text="Hello",
        )
        results = await plugin.run(https_target)
        rule_ids = [r.rule_id for r in results]
        assert "ssl_no_hsts" not in rule_ids
        assert "ssl_hsts_max_age_low" not in rule_ids

    @pytest.mark.asyncio
    async def test_non_https_target_skipped(self, plugin, httpx_mock):
        """Non-HTTPS (http://) target is skipped entirely."""
        target = Target(url="http://example.com")
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_hsts_low_max_age_reported(self, plugin, https_target, httpx_mock):
        """HSTS with max-age below threshold triggers ssl_hsts_max_age_low."""
        httpx_mock.add_response(
            url="https://example.com",
            status_code=200,
            headers={"Strict-Transport-Security": "max-age=3600"},
            text="Hello",
        )
        results = await plugin.run(https_target)
        rule_ids = [r.rule_id for r in results]
        assert "ssl_hsts_max_age_low" in rule_ids

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, https_target, httpx_mock):
        """Transport / SSL errors return empty results."""
        httpx_mock.add_exception(httpx.ConnectError("SSL handshake failed"))
        results = await plugin.run(https_target)
        assert results == []
