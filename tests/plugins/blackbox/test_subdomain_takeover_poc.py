# tests/plugins/blackbox/test_subdomain_takeover_poc.py
"""Tests for subdomain takeover PoC confirmation plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.subdomain_takeover_poc import SubdomainTakeoverPocPlugin
from vibee_hacker.core.models import Target, Severity, InterPhaseContext


class TestSubdomainTakeoverPoc:
    @pytest.fixture
    def plugin(self):
        return SubdomainTakeoverPocPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="http://example.com/")

    @pytest.mark.asyncio
    async def test_takeover_confirmable_with_dangling_cname(self, plugin, target, httpx_mock):
        """Dangling CNAME returning service-specific error is reported as HIGH."""
        context = InterPhaseContext(dangling_cnames=["unclaimed.s3.amazonaws.com"])
        httpx_mock.add_response(
            url="http://unclaimed.s3.amazonaws.com/",
            status_code=404,
            text="NoSuchBucket",
        )
        results = await plugin.run(target, context)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.HIGH
        assert results[0].rule_id == "subdomain_takeover_confirmed"
        assert results[0].cwe_id == "CWE-284"

    @pytest.mark.asyncio
    async def test_cname_resolves_normally(self, plugin, target, httpx_mock):
        """CNAME that resolves to a live site produces no results."""
        context = InterPhaseContext(dangling_cnames=["live-service.example.net"])
        httpx_mock.add_response(
            url="http://live-service.example.net/",
            status_code=200,
            text="<html><body>Live service working fine</body></html>",
        )
        results = await plugin.run(target, context)
        assert results == []

    @pytest.mark.asyncio
    async def test_no_dangling_cnames_skips(self, plugin, target):
        """No dangling cnames in context returns empty without making requests."""
        context = InterPhaseContext(dangling_cnames=[])
        results = await plugin.run(target, context)
        assert results == []

    @pytest.mark.asyncio
    async def test_no_context_skips(self, plugin, target):
        """No context at all returns empty without making requests."""
        results = await plugin.run(target, None)
        assert results == []
