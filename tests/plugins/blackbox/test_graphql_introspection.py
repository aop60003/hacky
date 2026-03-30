# tests/plugins/blackbox/test_graphql_introspection.py
"""Tests for GraphQL introspection detection plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.graphql_introspection import GraphqlIntrospectionPlugin
from vibee_hacker.core.models import Target, Severity


class TestGraphqlIntrospection:
    @pytest.fixture
    def plugin(self):
        return GraphqlIntrospectionPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/")

    @pytest.mark.asyncio
    async def test_introspection_returns_schema(self, plugin, target, httpx_mock):
        """GraphQL endpoint returning __schema with types is reported as HIGH."""
        from vibee_hacker.plugins.blackbox.graphql_introspection import GRAPHQL_PATHS
        # First path returns introspection data
        httpx_mock.add_response(
            url=f"https://example.com{GRAPHQL_PATHS[0]}",
            status_code=200,
            text='{"data": {"__schema": {"types": [{"name": "Query"}, {"name": "Mutation"}]}}}',
            headers={"Content-Type": "application/json"},
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.HIGH
        assert results[0].rule_id == "graphql_introspection_enabled"
        assert results[0].cwe_id == "CWE-200"

    @pytest.mark.asyncio
    async def test_introspection_disabled(self, plugin, target, httpx_mock):
        """GraphQL endpoint that disables introspection produces no results."""
        from vibee_hacker.plugins.blackbox.graphql_introspection import GRAPHQL_PATHS
        for path in GRAPHQL_PATHS:
            httpx_mock.add_response(
                url=f"https://example.com{path}",
                status_code=200,
                text='{"errors": [{"message": "GraphQL introspection is not allowed"}]}',
            )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_no_graphql_endpoint(self, plugin, target, httpx_mock):
        """All GraphQL probe paths returning 404 produce no results."""
        from vibee_hacker.plugins.blackbox.graphql_introspection import GRAPHQL_PATHS
        for _ in range(len(GRAPHQL_PATHS)):
            httpx_mock.add_response(status_code=404, text="Not Found")
        results = await plugin.run(target)
        assert len(results) == 0
