# tests/plugins/blackbox/test_http_smuggling.py
"""Tests for HTTP request smuggling detection plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.http_smuggling import HttpSmugglingPlugin
from vibee_hacker.core.models import Target, Severity


class TestHttpSmuggling:
    @pytest.fixture
    def plugin(self):
        return HttpSmugglingPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="http://example.com/")

    @pytest.mark.asyncio
    async def test_timing_anomaly_detected(self, plugin, target, httpx_mock):
        """Probe returning 400 when baseline is 200 is reported as CRITICAL."""
        # Baseline: normal POST returns 200
        httpx_mock.add_response(
            url="http://example.com/",
            status_code=200,
            text="OK",
        )
        # CL.TE probe: server responds with 400 indicating framing confusion
        httpx_mock.add_response(
            url="http://example.com/",
            status_code=400,
            text="Bad Request: invalid chunk size",
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.CRITICAL
        assert results[0].rule_id == "http_smuggling_clte"
        assert results[0].cwe_id == "CWE-444"

    @pytest.mark.asyncio
    async def test_normal_200_response_returns_empty(self, plugin, target, httpx_mock):
        """Normal 200 response to both baseline and probe produces no results."""
        # Baseline
        httpx_mock.add_response(
            url="http://example.com/",
            status_code=200,
            text="<html><body>OK</body></html>",
        )
        # Probe also 200
        httpx_mock.add_response(
            url="http://example.com/",
            status_code=200,
            text="<html><body>OK</body></html>",
        )
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_baseline_already_400_skipped(self, plugin, target, httpx_mock):
        """If baseline already returns 400, the probe is skipped to avoid false positives."""
        # Baseline returns 400 (server rejects all POSTs)
        httpx_mock.add_response(
            url="http://example.com/",
            status_code=400,
            text="Bad Request",
        )
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_transport_error_on_baseline_returns_empty(self, plugin, target, httpx_mock):
        """Transport error on baseline request is handled gracefully."""
        httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_transport_error_on_probe_returns_empty(self, plugin, target, httpx_mock):
        """Transport error on probe request (after successful baseline) is handled gracefully."""
        # Baseline succeeds
        httpx_mock.add_response(
            url="http://example.com/",
            status_code=200,
            text="OK",
        )
        # Probe fails
        httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        assert results == []
