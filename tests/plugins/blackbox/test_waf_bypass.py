# tests/plugins/blackbox/test_waf_bypass.py
"""Tests for WAF bypass detection plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.waf_bypass import WafBypassPlugin
from vibee_hacker.core.models import Target, Severity, InterPhaseContext


class TestWafBypass:
    @pytest.fixture
    def plugin(self):
        return WafBypassPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/")

    @pytest.fixture
    def waf_context(self):
        ctx = InterPhaseContext()
        ctx.waf_info = {"waf_name": "Generic WAF", "detected_by": "payload_probe"}
        return ctx

    @pytest.mark.asyncio
    async def test_encoded_payload_bypasses_waf(self, plugin, target, waf_context, httpx_mock):
        """Encoded payload getting 200 (not blocked) is reported as bypass."""
        # Plugin returns early after first non-blocked payload
        httpx_mock.add_response(
            status_code=200,
            text="<html>Normal content</html>",
        )
        results = await plugin.run(target, waf_context)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.HIGH
        assert results[0].rule_id == "waf_bypass_possible"
        assert results[0].cwe_id == "CWE-693"

    @pytest.mark.asyncio
    async def test_all_payloads_blocked(self, plugin, target, waf_context, httpx_mock):
        """All payloads blocked (403) produces no results."""
        # 5 payloads total in BYPASS_PAYLOADS
        for _ in range(5):
            httpx_mock.add_response(
                status_code=403,
                text="Request blocked by WAF",
            )
        results = await plugin.run(target, waf_context)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_no_waf_info_in_context_skipped(self, plugin, target, httpx_mock):
        """No waf_info in context means plugin skips entirely."""
        context = InterPhaseContext()  # waf_info is None
        results = await plugin.run(target, context)
        assert results == []

    @pytest.mark.asyncio
    async def test_no_context_skipped(self, plugin, target, httpx_mock):
        """None context means plugin skips entirely."""
        results = await plugin.run(target, None)
        assert results == []
