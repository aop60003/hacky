# tests/plugins/blackbox/test_ssti_advanced.py
"""Tests for Advanced SSTI detection plugin (engine-specific payloads)."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.ssti_advanced import SstiAdvancedPlugin
from vibee_hacker.core.models import Target, Severity


class TestSstiAdvanced:
    @pytest.fixture
    def plugin(self):
        return SstiAdvancedPlugin()

    @pytest.fixture
    def target_with_param(self):
        return Target(url="https://example.com/render?template=hello")

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_jinja2_payload_detected(self, plugin, target_with_param, httpx_mock):
        """Jinja2 {{7*7}} → '49' in response — CRITICAL, rule_id: ssti_jinja2."""
        # Baseline: no '49'
        httpx_mock.add_response(
            url="https://example.com/render?template=hello",
            status_code=200,
            text="<html>hello</html>",
        )
        # Injected response: contains '49'
        httpx_mock.add_response(
            status_code=200,
            text="<html>49</html>",
            is_reusable=True,
        )
        results = await plugin.run(target_with_param)
        assert len(results) >= 1
        assert results[0].cwe_id == "CWE-94"
        assert results[0].base_severity == Severity.CRITICAL
        assert "ssti_" in results[0].rule_id

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_twig_payload_detected(self, plugin, target_with_param, httpx_mock):
        """Twig {{7*'7'}} → '7777777' in response — CRITICAL."""
        # Baseline: no '7777777'
        httpx_mock.add_response(
            url="https://example.com/render?template=hello",
            status_code=200,
            text="<html>hello</html>",
        )
        # Response with '7777777' (Twig string repetition result)
        httpx_mock.add_response(
            status_code=200,
            text="<html>7777777</html>",
            is_reusable=True,
        )
        results = await plugin.run(target_with_param)
        assert len(results) >= 1
        assert results[0].cwe_id == "CWE-94"

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_no_evaluation_not_vulnerable(self, plugin, target_with_param, httpx_mock):
        """Payloads not evaluated — no results."""
        httpx_mock.add_response(
            status_code=200,
            text="<html>hello</html>",
            is_reusable=True,
        )
        results = await plugin.run(target_with_param)
        assert results == []

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_baseline_already_contains_result_not_vulnerable(
        self, plugin, target_with_param, httpx_mock
    ):
        """Baseline already contains '49' — no false positive."""
        httpx_mock.add_response(
            status_code=200,
            text="<html>The answer is 49 always</html>",
            is_reusable=True,
        )
        results = await plugin.run(target_with_param)
        assert results == []

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, httpx_mock):
        """TransportError returns empty list."""
        target = Target(url="https://down.example.com/render?t=x")
        httpx_mock.add_exception(httpx.ConnectError("connection refused"), is_reusable=True)
        results = await plugin.run(target)
        assert results == []
