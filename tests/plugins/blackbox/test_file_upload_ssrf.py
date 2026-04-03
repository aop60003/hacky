# tests/plugins/blackbox/test_file_upload_ssrf.py
"""Tests for FileUploadSsrfPlugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.file_upload_ssrf import FileUploadSsrfPlugin
from vibee_hacker.core.models import Target, Severity


class TestFileUploadSsrf:
    @pytest.fixture
    def plugin(self):
        return FileUploadSsrfPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/")

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_ssrf_indicator_in_response_detected(self, plugin, target, httpx_mock):
        """Upload response containing SSRF indicator is flagged."""
        httpx_mock.add_response(
            status_code=200,
            text='{"status": "processed", "error": "network error connecting to vibee-ssrf-probe.internal"}',
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert r.rule_id == "file_upload_ssrf"
        assert r.cwe_id == "CWE-918"
        assert r.base_severity == Severity.HIGH

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False, assert_all_responses_were_requested=False)
    async def test_404_endpoints_no_findings(self, plugin, target, httpx_mock):
        """All upload endpoints returning 404 produce no results."""
        for _ in range(50):
            httpx_mock.add_response(status_code=404, text="Not Found")
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_transport_error_returns_empty(self, plugin, target, httpx_mock):
        """Transport errors return empty results."""
        httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        assert results == []
