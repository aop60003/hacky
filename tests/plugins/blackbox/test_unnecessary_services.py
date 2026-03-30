# tests/plugins/blackbox/test_unnecessary_services.py
"""Tests for unnecessary services exposure plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.unnecessary_services import UnnecessaryServicesPlugin, SERVICE_PATHS
from vibee_hacker.core.models import Target, Severity


class TestUnnecessaryServices:
    @pytest.fixture
    def plugin(self):
        return UnnecessaryServicesPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/")

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_responses_were_requested=False)
    async def test_actuator_env_returns_200_with_json(self, plugin, target, httpx_mock):
        """/actuator/env returning 200 with JSON content is reported as CRITICAL.

        The plugin stops at the first finding so responses registered for paths after
        /actuator/env will not be consumed. The httpx_mock marker disables the strict
        'all responses must be requested' assertion.
        """
        for path, _ in SERVICE_PATHS:
            if path == "/actuator/env":
                httpx_mock.add_response(
                    url=f"https://example.com{path}",
                    status_code=200,
                    text='{"activeProfiles": ["prod"], "propertySources": [{"name": "systemEnvironment", "properties": {"DB_PASSWORD": {"value": "secret"}}}]}',
                )
            else:
                httpx_mock.add_response(
                    url=f"https://example.com{path}",
                    status_code=404,
                    text="Not Found",
                )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.CRITICAL
        assert results[0].rule_id == "unnecessary_service_exposed"
        assert results[0].cwe_id == "CWE-16"

    @pytest.mark.asyncio
    async def test_all_return_404(self, plugin, target, httpx_mock):
        """All probed service paths returning 404 produce no results."""
        from vibee_hacker.plugins.blackbox.unnecessary_services import SERVICE_PATHS
        for _ in range(len(SERVICE_PATHS)):
            httpx_mock.add_response(status_code=404, text="Not Found")
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, target, httpx_mock):
        """Transport error on all service paths returns empty results gracefully."""
        from vibee_hacker.plugins.blackbox.unnecessary_services import SERVICE_PATHS
        for _ in range(len(SERVICE_PATHS)):
            httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        assert results == []
