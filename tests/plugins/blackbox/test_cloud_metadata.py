# tests/plugins/blackbox/test_cloud_metadata.py
"""Tests for cloud metadata via SSRF plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.cloud_metadata import CloudMetadataPlugin
from vibee_hacker.core.models import Target, Severity, InterPhaseContext


class TestCloudMetadata:
    @pytest.fixture
    def plugin(self):
        return CloudMetadataPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="http://example.com/")

    @pytest.mark.asyncio
    async def test_ssrf_returns_metadata(self, plugin, target, httpx_mock):
        """SSRF endpoint returning AWS metadata is reported as CRITICAL."""
        context = InterPhaseContext(ssrf_endpoints=["http://example.com/api/fetch?url="])
        # The plugin probes the SSRF endpoint with the metadata URL
        httpx_mock.add_response(
            status_code=200,
            text="ami-id\nami-launch-index\niam/security-credentials/role-name\ninstance-id",
        )
        results = await plugin.run(target, context)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.CRITICAL
        assert results[0].rule_id == "cloud_metadata_via_ssrf"
        assert results[0].cwe_id == "CWE-918"

    @pytest.mark.asyncio
    async def test_no_ssrf_endpoints_skips(self, plugin, target):
        """No ssrf_endpoints in context skips the plugin entirely."""
        context = InterPhaseContext(ssrf_endpoints=[])
        results = await plugin.run(target, context)
        assert results == []

    @pytest.mark.asyncio
    async def test_no_context_skips(self, plugin, target):
        """No context at all skips the plugin entirely."""
        results = await plugin.run(target, None)
        assert results == []

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, target, httpx_mock):
        """Transport error on SSRF probe is handled gracefully."""
        from vibee_hacker.plugins.blackbox.cloud_metadata import METADATA_URLS
        context = InterPhaseContext(ssrf_endpoints=["http://example.com/api/fetch?url="])
        # Register an exception for each metadata URL that will be probed
        for _ in range(len(METADATA_URLS)):
            httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target, context)
        assert results == []
