# tests/plugins/blackbox/test_cloud_service_misconfig.py
"""Tests for cloud service misconfiguration detection plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.cloud_service_misconfig import CloudServiceMisconfigPlugin
from vibee_hacker.core.models import Target, Severity


class TestCloudServiceMisconfig:
    @pytest.fixture
    def plugin(self):
        return CloudServiceMisconfigPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://myapp.firebaseio.com/")

    @pytest.mark.asyncio
    async def test_firebase_json_returns_data(self, plugin, target, httpx_mock):
        """Firebase .json endpoint returning data triggers CRITICAL finding."""
        httpx_mock.add_response(
            url="https://myapp.firebaseio.com/.json",
            status_code=200,
            json={"users": {"alice": {"email": "alice@example.com"}}},
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.CRITICAL
        assert "cloud_misconfig" in results[0].rule_id
        assert results[0].cwe_id == "CWE-16"

    @pytest.mark.asyncio
    async def test_all_probes_fail(self, plugin, target, httpx_mock):
        """All probes returning 401/403/404 produces no results."""
        # Firebase probe returns 401
        httpx_mock.add_response(
            url="https://myapp.firebaseio.com/.json",
            status_code=401,
            text='{"error": "Permission denied"}',
        )
        # AWS IMDS probe (404 or transport error from mock)
        httpx_mock.add_response(
            url="http://169.254.169.254/latest/meta-data/",
            status_code=404,
            text="Not found",
        )
        # Kubernetes probe
        httpx_mock.add_response(
            url="https://myapp.firebaseio.com/api/v1/namespaces",
            status_code=403,
            text='{"message": "Forbidden"}',
        )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, target, httpx_mock):
        """Transport error returns empty results gracefully."""
        httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        assert results == []
