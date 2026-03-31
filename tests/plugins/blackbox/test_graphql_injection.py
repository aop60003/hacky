# tests/plugins/blackbox/test_graphql_injection.py
"""Tests for GraphQL SQL/NoSQL injection detection plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.graphql_injection import GraphqlInjectionPlugin
from vibee_hacker.core.models import Target, Severity


class TestGraphqlInjection:
    @pytest.fixture
    def plugin(self):
        return GraphqlInjectionPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/")

    @pytest.mark.asyncio
    async def test_sql_error_in_graphql_response(self, plugin, target, httpx_mock):
        """SQL error in GraphQL response is reported as CRITICAL."""
        from vibee_hacker.plugins.blackbox.graphql_injection import GRAPHQL_PATHS
        # First path returns SQL error
        httpx_mock.add_response(
            url=f"https://example.com{GRAPHQL_PATHS[0]}",
            status_code=200,
            text='{"errors": [{"message": "You have an error in your SQL syntax near \'1\' OR \'1\'=\'1\'"}]}',
            headers={"Content-Type": "application/json"},
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.CRITICAL
        assert results[0].rule_id == "graphql_sql_injection"
        assert results[0].cwe_id == "CWE-89"

    @pytest.mark.asyncio
    async def test_no_sql_error(self, plugin, target, httpx_mock):
        """Clean responses produce no results."""
        from vibee_hacker.plugins.blackbox.graphql_injection import GRAPHQL_PATHS
        for path in GRAPHQL_PATHS:
            # Each path gets multiple payload requests (2 payloads)
            httpx_mock.add_response(
                url=f"https://example.com{path}",
                status_code=200,
                text='{"data": {"user": {"name": "Alice"}}}',
            )
            httpx_mock.add_response(
                url=f"https://example.com{path}",
                status_code=200,
                text='{"data": {"user": {"name": "Alice"}}}',
            )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_no_graphql_endpoint_all_404(self, plugin, target, httpx_mock):
        """All GraphQL probe paths returning 404 produce no results."""
        from vibee_hacker.plugins.blackbox.graphql_injection import GRAPHQL_PATHS
        # Each path gets multiple payload requests
        for _ in range(len(GRAPHQL_PATHS) * 2):
            httpx_mock.add_response(status_code=404, text="Not Found")
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, httpx_mock):
        """TransportError on all endpoints returns empty list."""
        target = Target(url="https://down.example.com/")
        httpx_mock.add_exception(httpx.ConnectError("connection refused"), is_reusable=True)
        results = await plugin.run(target)
        assert results == []
