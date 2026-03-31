# tests/plugins/blackbox/test_graphql_depth_limit.py
"""Tests for GraphQL depth limit detection plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.graphql_depth_limit import GraphqlDepthLimitPlugin
from vibee_hacker.core.models import Target, Severity


class TestGraphqlDepthLimit:
    @pytest.fixture
    def plugin(self):
        return GraphqlDepthLimitPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/")

    @pytest.mark.asyncio
    async def test_deep_query_succeeds_is_vulnerable(self, plugin, target, httpx_mock):
        """Server returns 200 with data for deeply nested query — reported as HIGH."""
        from vibee_hacker.plugins.blackbox.graphql_depth_limit import GRAPHQL_PATHS
        httpx_mock.add_response(
            url=f"https://example.com{GRAPHQL_PATHS[0]}",
            status_code=200,
            text='{"data": {"a": {"b": {"c": {"d": {"e": {"f": {"g": {"h": {"i": {"j": {"name": "deep"}}}}}}}}}}}}',
            headers={"Content-Type": "application/json"},
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.HIGH
        assert results[0].rule_id == "graphql_no_depth_limit"
        assert results[0].cwe_id == "CWE-770"

    @pytest.mark.asyncio
    async def test_depth_limit_error_returned(self, plugin, target, httpx_mock):
        """Server returns depth limit error — not vulnerable."""
        from vibee_hacker.plugins.blackbox.graphql_depth_limit import GRAPHQL_PATHS
        for path in GRAPHQL_PATHS:
            httpx_mock.add_response(
                url=f"https://example.com{path}",
                status_code=200,
                text='{"errors": [{"message": "Query exceeds maximum depth of 5"}]}',
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
