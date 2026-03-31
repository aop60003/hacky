# tests/plugins/blackbox/test_business_logic.py
"""Tests for business logic flaw detection plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.business_logic import BusinessLogicPlugin
from vibee_hacker.core.models import Target, Severity


class TestBusinessLogic:
    @pytest.fixture
    def plugin(self):
        return BusinessLogicPlugin()

    @pytest.fixture
    def target_with_params(self):
        return Target(url="https://example.com/checkout?price=100&quantity=2")

    @pytest.mark.asyncio
    async def test_negative_price_accepted(self, plugin, target_with_params, httpx_mock):
        """200 OK response to negative price is a business logic flaw."""
        # Plugin returns early after first 200 response
        httpx_mock.add_response(
            status_code=200,
            json={"status": "success", "total": -100},
        )
        results = await plugin.run(target_with_params)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.HIGH
        assert results[0].rule_id == "business_logic_flaw"
        assert results[0].cwe_id == "CWE-840"

    @pytest.mark.asyncio
    async def test_negative_values_rejected(self, plugin, target_with_params, httpx_mock):
        """400 responses to negative values produce no results."""
        # 2 numeric params (price, quantity) * 3 payloads = 6 GET requests
        for _ in range(6):
            httpx_mock.add_response(
                status_code=400,
                json={"error": "Invalid value"},
            )
        results = await plugin.run(target_with_params)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_no_numeric_params_skipped(self, plugin, httpx_mock):
        """URL with no numeric params is skipped without making requests."""
        target = Target(url="https://example.com/profile?user=alice")
        results = await plugin.run(target)
        assert results == []
