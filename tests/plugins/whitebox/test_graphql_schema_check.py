# tests/plugins/whitebox/test_graphql_schema_check.py
"""Tests for GraphQLSchemaCheckPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.graphql_schema_check import GraphQLSchemaCheckPlugin
from vibee_hacker.core.models import Target, Severity


class TestGraphQLSchemaCheck:
    @pytest.fixture
    def plugin(self):
        return GraphQLSchemaCheckPlugin()

    # ------------------------------------------------------------------ #
    # Test 1: Mutation without auth + deep nesting detected
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_mutation_without_auth_detected(self, plugin, tmp_path):
        """Mutations without @auth directive are flagged."""
        (tmp_path / "schema.graphql").write_text(
            "type Query {\n"
            "  hello: String\n"
            "}\n"
            "type Mutation {\n"
            "  createUser(name: String!): User\n"
            "  deleteUser(id: ID!): Boolean\n"
            "}\n"
            "type User {\n"
            "  id: ID!\n"
            "  name: String\n"
            "  friends: [Friend]\n"
            "}\n"
            "type Friend {\n"
            "  id: ID!\n"
            "  user: User\n"
            "  connections: [Connection]\n"
            "}\n"
            "type Connection {\n"
            "  id: ID!\n"
            "  friend: Friend\n"
            "  mutual: [User]\n"
            "}\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        rule_ids = [r.rule_id for r in results]
        assert any("graphql_schema_" in rid for rid in rule_ids)
        assert any("graphql_schema_unauth_mutation" in rid for rid in rule_ids)
        for r in results:
            assert r.cwe_id == "CWE-862"

    # ------------------------------------------------------------------ #
    # Test 2: Protected schema — no findings
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_protected_schema_no_findings(self, plugin, tmp_path):
        """A schema with @auth directives produces no mutation findings."""
        (tmp_path / "schema.graphql").write_text(
            "directive @auth on FIELD_DEFINITION\n"
            "type Query {\n"
            "  hello: String\n"
            "}\n"
            "type Mutation {\n"
            "  createUser(name: String!): User @auth\n"
            "  deleteUser(id: ID!): Boolean @auth\n"
            "}\n"
            "type User {\n"
            "  id: ID!\n"
            "  name: String\n"
            "}\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        unauth = [r for r in results if r.rule_id == "graphql_schema_unauth_mutation"]
        assert unauth == []

    # ------------------------------------------------------------------ #
    # Test 3: No graphql files — returns empty
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_no_graphql_files_returns_empty(self, plugin, tmp_path):
        """Directories without GraphQL files produce no results."""
        (tmp_path / "app.py").write_text("print('hello')\n")
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert results == []
