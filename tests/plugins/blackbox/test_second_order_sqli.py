# tests/plugins/blackbox/test_second_order_sqli.py
"""Tests for SecondOrderSqliPlugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.second_order_sqli import SecondOrderSqliPlugin
from vibee_hacker.core.models import Target, Severity


class TestSecondOrderSqli:
    @pytest.fixture
    def plugin(self):
        return SecondOrderSqliPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/")

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_sql_error_in_retrieval_detected(self, plugin, target, httpx_mock):
        """SQL error triggered in retrieval page after storing payload is flagged."""
        # Registration POST succeeds
        httpx_mock.add_response(
            status_code=200,
            text='{"status": "registered"}',
        )
        # Retrieval GET returns SQL error
        httpx_mock.add_response(
            status_code=500,
            text="You have an error in your SQL syntax near 'vibee' at line 1",
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert r.rule_id == "second_order_sqli"
        assert r.cwe_id == "CWE-89"
        assert r.base_severity == Severity.CRITICAL

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_no_sql_errors_no_findings(self, plugin, target, httpx_mock):
        """No SQL errors in any responses produce no results."""
        for _ in range(100):
            httpx_mock.add_response(
                status_code=200,
                text='{"status": "ok"}',
            )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_transport_error_returns_empty(self, plugin, target, httpx_mock):
        """Transport errors return empty results."""
        httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        assert results == []
