# tests/plugins/blackbox/test_mixed_content.py
"""Tests for mixed content detection plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.mixed_content import MixedContentPlugin
from vibee_hacker.core.models import Target, Severity


class TestMixedContent:
    @pytest.fixture
    def plugin(self):
        return MixedContentPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com")

    @pytest.mark.asyncio
    async def test_http_script_src_found(self, plugin, target, httpx_mock):
        """http:// script src on HTTPS page is reported as HIGH (active mixed content)."""
        httpx_mock.add_response(
            url="https://example.com",
            headers={"Content-Type": "text/html"},
            text='<html><head><script src="http://cdn.example.com/app.js"></script></head><body></body></html>',
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.HIGH
        assert "mixed_content" in results[0].rule_id

    @pytest.mark.asyncio
    async def test_all_https_resources_no_results(self, plugin, target, httpx_mock):
        """All resources loaded over HTTPS → no results."""
        httpx_mock.add_response(
            url="https://example.com",
            headers={"Content-Type": "text/html"},
            text='<html><head><script src="https://cdn.example.com/app.js"></script></head><body><img src="https://img.example.com/photo.jpg"/></body></html>',
        )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_non_https_target_skipped(self, plugin, httpx_mock):
        """Non-HTTPS target is skipped (no results, no requests sent)."""
        http_target = Target(url="http://example.com")
        results = await plugin.run(http_target)
        assert results == []

    @pytest.mark.asyncio
    async def test_passive_http_img_src(self, plugin, target, httpx_mock):
        """http:// img src on HTTPS page is reported as MEDIUM (passive mixed content)."""
        httpx_mock.add_response(
            url="https://example.com",
            headers={"Content-Type": "text/html"},
            text='<html><body><img src="http://images.example.com/photo.jpg"/></body></html>',
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.MEDIUM
