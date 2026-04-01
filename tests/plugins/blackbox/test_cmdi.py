# tests/plugins/blackbox/test_cmdi.py
import pytest
import httpx
from vibee_hacker.plugins.blackbox.cmdi import CmdiPlugin
from vibee_hacker.core.models import Target, Severity


class TestCmdi:
    @pytest.fixture
    def plugin(self):
        return CmdiPlugin()

    @pytest.mark.asyncio
    async def test_output_based_detection(self, plugin, httpx_mock):
        target = Target(url="https://example.com/ping?host=test")
        httpx_mock.add_response(
            url="https://example.com/ping?host=test",
            text="PING test",
        )
        httpx_mock.add_response(
            url="https://example.com/ping?host=test%3Becho+VIBEE_CMD_MARKER",
            text="PING test\nVIBEE_CMD_MARKER",
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.CRITICAL
        assert "CWE-78" in (results[0].cwe_id or "")

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_responses_were_requested=False, assert_all_requests_were_expected=False)
    async def test_no_cmdi(self, plugin, httpx_mock):
        target = Target(url="https://example.com/ping?host=test")
        # Return safe response for baseline + all payload requests + POST requests
        for _ in range(100):
            httpx_mock.add_response(text="PING test")
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_transport_error_returns_empty(self, plugin, httpx_mock):
        target = Target(url="https://down.example.com/page?q=test")
        httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        assert results == []
