# tests/plugins/blackbox/test_container_orch_check.py
"""Tests for container orchestration API exposure plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.container_orch_check import ContainerOrchCheckPlugin
from vibee_hacker.core.models import Target, Severity


class TestContainerOrchCheck:
    @pytest.fixture
    def plugin(self):
        return ContainerOrchCheckPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="http://example.com/")

    @pytest.mark.asyncio
    async def test_docker_api_accessible_is_critical(self, plugin, target, httpx_mock):
        """Docker API returning version JSON is reported as CRITICAL."""
        from vibee_hacker.plugins.blackbox.container_orch_check import CONTAINER_ENDPOINTS
        # First endpoint returns Docker version response
        first_url = CONTAINER_ENDPOINTS[0]["url"].format(host="example.com")
        httpx_mock.add_response(
            url=first_url,
            status_code=200,
            json={"Version": "20.10.7", "ApiVersion": "1.41"},
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.CRITICAL
        assert results[0].rule_id == "container_api_exposed"
        assert results[0].cwe_id == "CWE-284"

    @pytest.mark.asyncio
    async def test_all_ports_closed_returns_empty(self, plugin, target, httpx_mock):
        """All endpoints returning connection errors produce no results."""
        from vibee_hacker.plugins.blackbox.container_orch_check import CONTAINER_ENDPOINTS
        for _ in range(len(CONTAINER_ENDPOINTS)):
            httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, target, httpx_mock):
        """Transport errors on all probes produce no results."""
        from vibee_hacker.plugins.blackbox.container_orch_check import CONTAINER_ENDPOINTS
        for _ in range(len(CONTAINER_ENDPOINTS)):
            httpx_mock.add_exception(httpx.TimeoutException("timed out"))
        results = await plugin.run(target)
        assert results == []
