# tests/plugins/blackbox/test_api_schema_exposure.py
"""Tests for API schema exposure plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.api_schema_exposure import ApiSchemaExposurePlugin
from vibee_hacker.core.models import Target, Severity


class TestApiSchemaExposure:
    @pytest.fixture
    def plugin(self):
        return ApiSchemaExposurePlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/")

    @pytest.mark.asyncio
    async def test_swagger_json_accessible(self, plugin, target, httpx_mock):
        """Publicly accessible swagger.json is reported as MEDIUM."""
        from vibee_hacker.plugins.blackbox.api_schema_exposure import SCHEMA_PATHS
        # First path returns swagger JSON
        httpx_mock.add_response(
            url=f"https://example.com{SCHEMA_PATHS[0]}",
            status_code=200,
            json={"openapi": "3.0.0", "paths": {"/api/v1/users": {}}},
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.MEDIUM
        assert results[0].rule_id == "api_schema_public"
        assert results[0].cwe_id == "CWE-200"

    @pytest.mark.asyncio
    async def test_all_return_401_or_404(self, plugin, target, httpx_mock):
        """All schema paths returning 401/404 produce no results."""
        from vibee_hacker.plugins.blackbox.api_schema_exposure import SCHEMA_PATHS
        for i, path in enumerate(SCHEMA_PATHS):
            status = 401 if i % 2 == 0 else 404
            httpx_mock.add_response(
                url=f"https://example.com{path}",
                status_code=status,
                text="Unauthorized" if status == 401 else "Not Found",
            )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, target, httpx_mock):
        """Transport error returns empty results gracefully."""
        from vibee_hacker.plugins.blackbox.api_schema_exposure import SCHEMA_PATHS
        for _ in SCHEMA_PATHS:
            httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        assert results == []
