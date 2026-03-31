# tests/plugins/blackbox/test_api_versioning_check.py
"""Tests for API versioning check plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.api_versioning_check import ApiVersioningCheckPlugin
from vibee_hacker.core.models import Target, Severity


class TestApiVersioningCheck:
    @pytest.fixture
    def plugin(self):
        return ApiVersioningCheckPlugin()

    @pytest.fixture
    def target_v2(self):
        return Target(url="https://example.com/api/v2/users")

    @pytest.fixture
    def target_no_version(self):
        return Target(url="https://example.com/api/users")

    @pytest.mark.asyncio
    async def test_old_version_still_active(self, plugin, target_v2, httpx_mock):
        """Old API version responding 200 is reported as MEDIUM."""
        httpx_mock.add_response(
            url="https://example.com/api/v1/",
            status_code=200,
            json={"status": "ok", "version": "v1"},
        )
        results = await plugin.run(target_v2)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.MEDIUM
        assert results[0].rule_id == "api_old_version_active"
        assert results[0].cwe_id == "CWE-1104"

    @pytest.mark.asyncio
    async def test_old_version_returns_404(self, plugin, target_v2, httpx_mock):
        """Old API version returning 404 produces no results."""
        httpx_mock.add_response(
            url="https://example.com/api/v1/",
            status_code=404,
            text="Not Found",
        )
        results = await plugin.run(target_v2)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_no_version_in_url(self, plugin, target_no_version, httpx_mock):
        """URL with no version pattern produces no results without HTTP calls."""
        results = await plugin.run(target_no_version)
        assert len(results) == 0
