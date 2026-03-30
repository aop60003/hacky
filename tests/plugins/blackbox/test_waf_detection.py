# tests/plugins/blackbox/test_waf_detection.py
"""Tests for WAF detection plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.waf_detection import WafDetectionPlugin
from vibee_hacker.core.models import Target, Severity, InterPhaseContext


class TestWafDetection:
    @pytest.fixture
    def plugin(self):
        return WafDetectionPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/")

    @pytest.mark.asyncio
    async def test_waf_detected_via_cf_ray_header(self, plugin, target, httpx_mock):
        """WAF detected when cf-ray header is present."""
        httpx_mock.add_response(
            status_code=403,
            headers={"cf-ray": "abc123-LAX"},
            text="Access denied",
        )
        context = InterPhaseContext()
        results = await plugin.run(target, context)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.INFO
        assert results[0].rule_id == "waf_detected"
        assert context.waf_info is not None
        assert "cloudflare" in context.waf_info.get("waf_name", "").lower()

    @pytest.mark.asyncio
    async def test_no_waf_present(self, plugin, target, httpx_mock):
        """No WAF when response is normal 200."""
        httpx_mock.add_response(
            status_code=200,
            text="<html>Normal page</html>",
        )
        httpx_mock.add_response(
            status_code=200,
            text="<html>Normal page</html>",
        )
        context = InterPhaseContext()
        results = await plugin.run(target, context)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, target, httpx_mock):
        """Transport error returns empty results gracefully."""
        httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        context = InterPhaseContext()
        results = await plugin.run(target, context)
        assert results == []
