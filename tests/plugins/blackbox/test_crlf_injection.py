# tests/plugins/blackbox/test_crlf_injection.py
"""Tests for CRLF injection detection plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.crlf_injection import CrlfInjectionPlugin
from vibee_hacker.core.models import Target, Severity


class TestCrlfInjection:
    @pytest.fixture
    def plugin(self):
        return CrlfInjectionPlugin()

    @pytest.mark.asyncio
    async def test_injected_header_in_response(self, plugin, httpx_mock):
        """Injected header appearing in response is reported as HIGH."""
        target = Target(url="https://example.com/page?q=test")
        httpx_mock.add_response(
            status_code=200,
            headers={"x-injected": "true"},
            text="<html>page</html>",
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.HIGH
        assert results[0].rule_id == "crlf_header_injection"
        assert results[0].cwe_id == "CWE-113"

    @pytest.mark.asyncio
    async def test_no_injection(self, plugin, httpx_mock):
        """Response without injected header returns no results."""
        target = Target(url="https://example.com/page?q=test")
        httpx_mock.add_response(
            status_code=200,
            headers={"content-type": "text/html"},
            text="<html>Normal page</html>",
        )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_no_params(self, plugin, httpx_mock):
        """URL without params returns no results."""
        target = Target(url="https://example.com/page")
        results = await plugin.run(target)
        assert len(results) == 0
