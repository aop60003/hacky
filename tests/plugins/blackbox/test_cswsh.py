# tests/plugins/blackbox/test_cswsh.py
"""Tests for CswshPlugin (Cross-Site WebSocket Hijacking)."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.cswsh import CswshPlugin
from vibee_hacker.core.models import Target, Severity


class TestCswsh:
    @pytest.fixture
    def plugin(self):
        return CswshPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/")

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_101_with_evil_origin_detected(self, plugin, target, httpx_mock):
        """HTTP 101 Switching Protocols with evil Origin is flagged as CSWSH."""
        httpx_mock.add_response(
            status_code=101,
            headers={
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Accept": "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
            },
            text="",
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert r.rule_id == "cswsh"
        assert r.base_severity == Severity.HIGH
        assert r.cwe_id == "CWE-346"

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False, assert_all_responses_were_requested=False)
    async def test_no_websocket_endpoints_no_findings(self, plugin, target, httpx_mock):
        """No WebSocket endpoints (all 404) produce no results."""
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
