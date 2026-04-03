# tests/plugins/blackbox/test_graphql_alias.py
"""Tests for GraphQL Alias Overloading detection plugin."""
import json
import pytest
import httpx
from vibee_hacker.plugins.blackbox.graphql_alias import (
    GraphqlAliasPlugin,
    GRAPHQL_PATHS,
    ALIAS_COUNT,
    _build_alias_query,
    _count_alias_results,
)
from vibee_hacker.core.models import Target, Severity


def _make_alias_response(count: int) -> str:
    data = {f"a{i}": "Query" for i in range(count)}
    return json.dumps({"data": data})


class TestGraphqlAlias:
    @pytest.fixture
    def plugin(self):
        return GraphqlAliasPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/")

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_all_aliases_returned_is_vulnerable(self, plugin, target, httpx_mock):
        """Server returns all aliases — reported as HIGH with correct rule_id."""
        httpx_mock.add_response(
            url=f"https://example.com{GRAPHQL_PATHS[0]}",
            status_code=200,
            text=_make_alias_response(ALIAS_COUNT),
            headers={"Content-Type": "application/json"},
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].rule_id == "graphql_alias_overload"
        assert results[0].cwe_id == "CWE-770"
        assert results[0].base_severity == Severity.HIGH

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_server_rejects_aliases(self, plugin, target, httpx_mock):
        """Server rejects alias query with 400 — no results."""
        for path in GRAPHQL_PATHS:
            httpx_mock.add_response(
                url=f"https://example.com{path}",
                status_code=400,
                text='{"errors": [{"message": "Alias limit exceeded"}]}',
            )
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, httpx_mock):
        """TransportError returns empty list."""
        target = Target(url="https://down.example.com/")
        httpx_mock.add_exception(httpx.ConnectError("connection refused"), is_reusable=True)
        results = await plugin.run(target)
        assert results == []

    def test_build_alias_query_contains_expected_aliases(self):
        """Helper builds query with correct alias count."""
        query = _build_alias_query(5)
        for i in range(5):
            assert f"a{i}: __typename" in query

    def test_count_alias_results_detects_full_response(self):
        """Helper correctly counts alias keys in JSON response."""
        response = _make_alias_response(ALIAS_COUNT)
        assert _count_alias_results(response, ALIAS_COUNT) is True

    def test_count_alias_results_partial_false(self):
        """Helper returns False when not enough aliases present."""
        response = _make_alias_response(10)
        assert _count_alias_results(response, ALIAS_COUNT) is False
