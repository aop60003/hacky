# tests/plugins/blackbox/test_mass_assignment.py
"""Tests for mass assignment detection plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.mass_assignment import MassAssignmentPlugin
from vibee_hacker.core.models import Target, Severity


class TestMassAssignment:
    @pytest.fixture
    def plugin(self):
        return MassAssignmentPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/api/user")

    @pytest.mark.asyncio
    async def test_role_admin_reflected_in_response(self, plugin, target, httpx_mock):
        """Extra fields like 'role':'admin' reflected in response are reported as HIGH."""
        # Baseline response (normal POST)
        httpx_mock.add_response(
            url="https://example.com/api/user",
            status_code=200,
            text='{"id": 1, "name": "test"}',
        )
        # Mass assignment POST response
        httpx_mock.add_response(
            url="https://example.com/api/user",
            status_code=200,
            text='{"id": 1, "name": "test", "role": "admin", "is_admin": true}',
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.HIGH
        assert results[0].rule_id == "mass_assignment"
        assert results[0].cwe_id == "CWE-915"

    @pytest.mark.asyncio
    async def test_extra_fields_ignored(self, plugin, target, httpx_mock):
        """Response not reflecting extra fields produces no results."""
        # Baseline response
        httpx_mock.add_response(
            url="https://example.com/api/user",
            status_code=200,
            text='{"id": 1, "name": "test"}',
        )
        # Mass assignment POST - same response, fields ignored
        httpx_mock.add_response(
            url="https://example.com/api/user",
            status_code=200,
            text='{"id": 1, "name": "test"}',
        )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_no_url_returns_empty(self, plugin, httpx_mock):
        """Target without URL returns empty results."""
        target = Target(url=None)
        results = await plugin.run(target)
        assert results == []
