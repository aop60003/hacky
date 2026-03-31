# tests/plugins/blackbox/test_bfla.py
"""Tests for Broken Function Level Authorization (BFLA) detection plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.bfla import BflaPlugin
from vibee_hacker.core.models import Target, Severity


class TestBfla:
    @pytest.fixture
    def plugin(self):
        return BflaPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/")

    @pytest.mark.asyncio
    async def test_admin_path_returns_200_with_data(self, plugin, target, httpx_mock):
        """/admin returns 200 with data on first probe — reported as CRITICAL."""
        # Register /admin as immediately returning 200 (first path tried)
        httpx_mock.add_response(
            url="https://example.com/admin",
            status_code=200,
            text='{"users": [{"id": 1, "role": "admin"}]}',
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.CRITICAL
        assert results[0].rule_id == "bfla_admin_access"
        assert results[0].cwe_id == "CWE-285"

    @pytest.mark.asyncio
    async def test_all_admin_paths_return_403(self, plugin, target, httpx_mock):
        """All admin paths returning 403 produce no results."""
        from vibee_hacker.plugins.blackbox.bfla import ADMIN_PATHS
        for _ in ADMIN_PATHS:
            httpx_mock.add_response(status_code=403, text="Forbidden")
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, httpx_mock):
        """TransportError returns empty list."""
        target = Target(url="https://down.example.com/")
        httpx_mock.add_exception(httpx.ConnectError("connection refused"), is_reusable=True)
        results = await plugin.run(target)
        assert results == []
