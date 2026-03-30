# tests/plugins/blackbox/test_ssti.py
import pytest
import httpx
from vibee_hacker.plugins.blackbox.ssti import SstiPlugin
from vibee_hacker.core.models import Target, Severity


class TestSsti:
    @pytest.fixture
    def plugin(self):
        return SstiPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/search?q=test")

    @pytest.mark.asyncio
    async def test_ssti_detected(self, plugin, target, httpx_mock):
        # Baseline does NOT contain 49
        httpx_mock.add_response(
            url="https://example.com/search?q=test",
            text="<html>Hello test</html>",
        )
        # First payload {{7*7}} reflected as 49
        httpx_mock.add_response(
            text="<html>Result: 49</html>",
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.CRITICAL
        assert results[0].cwe_id == "CWE-1336"
        assert results[0].rule_id == "ssti_math_reflection"

    @pytest.mark.asyncio
    async def test_no_ssti(self, plugin, target, httpx_mock):
        # Baseline and all payloads return normal page without 49
        # 1 baseline + 5 payloads = 6 requests total for 1 param
        httpx_mock.add_response(text="<html>Normal page</html>")
        for _ in range(5):
            httpx_mock.add_response(text="<html>Normal page</html>")
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_baseline_has_49(self, plugin, target, httpx_mock):
        # Baseline already contains 49 — should NOT report
        httpx_mock.add_response(
            url="https://example.com/search?q=test",
            text="<html>Score: 49 points</html>",
        )
        # Payloads also return 49 but baseline already had it
        for _ in range(5):
            httpx_mock.add_response(text="<html>Score: 49 points reflected</html>")
        results = await plugin.run(target)
        assert len(results) == 0
