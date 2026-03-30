# tests/plugins/blackbox/test_header_check.py
import pytest
import httpx
from vibee_hacker.plugins.blackbox.header_check import HeaderCheckPlugin
from vibee_hacker.core.models import Target, Severity


class TestHeaderCheck:
    @pytest.fixture
    def plugin(self):
        return HeaderCheckPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com")

    @pytest.mark.asyncio
    async def test_missing_all_headers(self, plugin, target, httpx_mock):
        httpx_mock.add_response(url="https://example.com", headers={})
        results = await plugin.run(target)
        assert len(results) >= 4  # CSP, X-Frame-Options, HSTS, X-Content-Type-Options
        titles = [r.title for r in results]
        assert any("Content-Security-Policy" in t for t in titles)
        assert any("X-Frame-Options" in t for t in titles)

    @pytest.mark.asyncio
    async def test_all_headers_present(self, plugin, target, httpx_mock):
        httpx_mock.add_response(
            url="https://example.com",
            headers={
                "Content-Security-Policy": "default-src 'self'",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Strict-Transport-Security": "max-age=31536000",
                "Referrer-Policy": "strict-origin",
                "Permissions-Policy": "camera=()",
            },
        )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_severity_is_medium(self, plugin, target, httpx_mock):
        httpx_mock.add_response(url="https://example.com", headers={})
        results = await plugin.run(target)
        assert all(r.base_severity == Severity.MEDIUM for r in results)
