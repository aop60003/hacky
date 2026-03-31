# tests/plugins/blackbox/test_xpath_injection.py
"""Tests for XPath injection detection plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.xpath_injection import XpathInjectionPlugin, PAYLOADS
from vibee_hacker.core.models import Target, Severity


class TestXpathInjection:
    @pytest.fixture
    def plugin(self):
        return XpathInjectionPlugin()

    @pytest.fixture
    def target_with_params(self):
        return Target(url="https://example.com/api/search?q=test&id=1")

    @pytest.fixture
    def target_no_params(self):
        return Target(url="https://example.com/api/search")

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_responses_were_requested=False)
    async def test_xpath_error_detected(self, plugin, target_with_params, httpx_mock):
        """XPath error in response is reported as HIGH.

        Plugin stops on first finding, so not all registered responses will be consumed.
        """
        # Register enough responses for all params x payloads — plugin will stop early
        for _ in range(len(PAYLOADS) * 2):
            httpx_mock.add_response(
                status_code=500,
                text="xmlXPathEval: evaluation failed\nXPath error: undefined",
            )
        results = await plugin.run(target_with_params)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.HIGH
        assert results[0].rule_id == "xpath_injection"
        assert results[0].cwe_id == "CWE-643"

    @pytest.mark.asyncio
    async def test_no_error_no_finding(self, plugin, target_with_params, httpx_mock):
        """Normal responses to all XPath payloads produce no results."""
        # 2 params * len(PAYLOADS) requests
        for _ in range(len(PAYLOADS) * 2):
            httpx_mock.add_response(
                status_code=200,
                text='{"results": []}',
            )
        results = await plugin.run(target_with_params)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_no_params_skipped(self, plugin, target_no_params, httpx_mock):
        """URL with no query params is skipped and produces no results."""
        results = await plugin.run(target_no_params)
        assert len(results) == 0
