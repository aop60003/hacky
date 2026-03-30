# tests/plugins/blackbox/test_cors_check.py
import pytest
import httpx
from vibee_hacker.plugins.blackbox.cors_check import CorsCheckPlugin
from vibee_hacker.core.models import Target, Severity


class TestCorsCheck:
    @pytest.fixture
    def plugin(self):
        return CorsCheckPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com")

    @pytest.mark.asyncio
    async def test_wildcard_origin_reflected(self, plugin, target, httpx_mock):
        httpx_mock.add_response(
            url="https://example.com",
            headers={"Access-Control-Allow-Origin": "https://evil.com"},
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_no_cors_headers(self, plugin, target, httpx_mock):
        httpx_mock.add_response(url="https://example.com", headers={})
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_wildcard_with_credentials(self, plugin, target, httpx_mock):
        httpx_mock.add_response(
            url="https://example.com",
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            },
        )
        results = await plugin.run(target)
        assert any("Credentials" in r.title for r in results)
