# tests/plugins/blackbox/test_cache_poisoning.py
"""Tests for cache poisoning via header reflection detection plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.cache_poisoning import CachePoisoningPlugin
from vibee_hacker.core.models import Target, Severity


class TestCachePoisoning:
    @pytest.fixture
    def plugin(self):
        return CachePoisoningPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/")

    @pytest.mark.asyncio
    async def test_forwarded_host_reflected_in_cached_response(self, plugin, target, httpx_mock):
        """X-Forwarded-Host reflected in body with cache headers — reported as HIGH."""
        from vibee_hacker.plugins.blackbox.cache_poisoning import EVIL_HOST
        httpx_mock.add_response(
            url="https://example.com/",
            status_code=200,
            text=f'<html><a href="https://{EVIL_HOST}/resource">link</a></html>',
            headers={
                "X-Cache": "HIT",
                "Cache-Control": "public, max-age=3600",
            },
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.HIGH
        assert results[0].rule_id == "cache_poisoning_header_reflected"
        assert results[0].cwe_id == "CWE-444"

    @pytest.mark.asyncio
    async def test_not_reflected(self, plugin, target, httpx_mock):
        """Evil host not reflected in response — no results."""
        httpx_mock.add_response(
            url="https://example.com/",
            status_code=200,
            text="<html>Normal page without evil host</html>",
            headers={"Cache-Control": "no-store"},
        )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, httpx_mock):
        """TransportError returns empty list."""
        target = Target(url="https://down.example.com/")
        httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        assert results == []
