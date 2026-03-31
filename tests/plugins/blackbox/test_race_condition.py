# tests/plugins/blackbox/test_race_condition.py
"""Tests for race condition detection plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.race_condition import RaceConditionPlugin
from vibee_hacker.core.models import Target, Severity


class TestRaceCondition:
    @pytest.fixture
    def plugin(self):
        return RaceConditionPlugin()

    @pytest.fixture
    def order_target(self):
        return Target(url="https://example.com/order")

    @pytest.mark.asyncio
    async def test_different_responses_detected(self, plugin, order_target, httpx_mock):
        """Concurrent responses with different data triggers HIGH finding."""
        # 5 concurrent requests, responses have different order IDs
        httpx_mock.add_response(status_code=200, json={"order_id": 1001, "status": "created"})
        httpx_mock.add_response(status_code=200, json={"order_id": 1002, "status": "created"})
        httpx_mock.add_response(status_code=200, json={"order_id": 1001, "status": "created"})
        httpx_mock.add_response(status_code=200, json={"order_id": 1001, "status": "created"})
        httpx_mock.add_response(status_code=200, json={"order_id": 1001, "status": "created"})
        results = await plugin.run(order_target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.HIGH
        assert results[0].rule_id == "race_condition_detected"
        assert results[0].cwe_id == "CWE-362"

    @pytest.mark.asyncio
    async def test_all_responses_same(self, plugin, order_target, httpx_mock):
        """Identical concurrent responses produce no results."""
        for _ in range(5):
            httpx_mock.add_response(status_code=200, json={"order_id": 1001, "status": "created"})
        results = await plugin.run(order_target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_non_matching_url_skipped(self, plugin, httpx_mock):
        """URL not matching order/transfer/buy patterns is skipped."""
        target = Target(url="https://example.com/profile")
        results = await plugin.run(target)
        assert results == []
