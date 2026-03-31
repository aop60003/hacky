# tests/plugins/blackbox/test_graphql_batch_attack.py
"""Tests for GraphQL batch attack detection plugin."""
import pytest
import httpx
import json
from vibee_hacker.plugins.blackbox.graphql_batch_attack import GraphqlBatchAttackPlugin
from vibee_hacker.core.models import Target, Severity


class TestGraphqlBatchAttack:
    @pytest.fixture
    def plugin(self):
        return GraphqlBatchAttackPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/")

    @pytest.mark.asyncio
    async def test_50_results_returned_is_vulnerable(self, plugin, target, httpx_mock):
        """Server returns array of 50 results — batch limiting absent, reported as HIGH."""
        from vibee_hacker.plugins.blackbox.graphql_batch_attack import GRAPHQL_PATHS, BATCH_SIZE
        batch_response = json.dumps([{"data": {"__typename": "Query"}} for _ in range(BATCH_SIZE)])
        httpx_mock.add_response(
            url=f"https://example.com{GRAPHQL_PATHS[0]}",
            status_code=200,
            text=batch_response,
            headers={"Content-Type": "application/json"},
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.HIGH
        assert results[0].rule_id == "graphql_no_batch_limit"
        assert results[0].cwe_id == "CWE-770"

    @pytest.mark.asyncio
    async def test_batch_rejected(self, plugin, target, httpx_mock):
        """Server rejects or limits batch — not vulnerable."""
        from vibee_hacker.plugins.blackbox.graphql_batch_attack import GRAPHQL_PATHS
        for path in GRAPHQL_PATHS:
            httpx_mock.add_response(
                url=f"https://example.com{path}",
                status_code=400,
                text='{"errors": [{"message": "Batching is not supported"}]}',
            )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, httpx_mock):
        """TransportError returns empty list."""
        target = Target(url="https://down.example.com/")
        httpx_mock.add_exception(httpx.ConnectError("connection refused"), is_reusable=True)
        results = await plugin.run(target)
        assert results == []
