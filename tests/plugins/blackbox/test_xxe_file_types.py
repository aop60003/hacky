# tests/plugins/blackbox/test_xxe_file_types.py
"""Tests for XxeFileTypesPlugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.xxe_file_types import XxeFileTypesPlugin
from vibee_hacker.core.models import Target, Severity


class TestXxeFileTypes:
    @pytest.fixture
    def plugin(self):
        return XxeFileTypesPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/")

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_xxe_file_contents_in_response_detected(self, plugin, target, httpx_mock):
        """Response containing /etc/passwd content is flagged as XXE."""
        httpx_mock.add_response(
            status_code=200,
            text='{"content": "root:x:0:0:root:/root:/bin/bash\\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"}',
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert "xxe" in r.rule_id.lower()
        assert r.cwe_id == "CWE-611"
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
