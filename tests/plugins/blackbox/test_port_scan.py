# tests/plugins/blackbox/test_port_scan.py
"""Tests for PortScanPlugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.port_scan import PortScanPlugin
from vibee_hacker.core.models import Target, Severity


class TestPortScan:
    @pytest.fixture
    def plugin(self):
        return PortScanPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="http://example.com/")

    # ------------------------------------------------------------------ #
    # Test 1: Port 8080 responds → reported
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_responses_were_requested=False)
    async def test_open_port_reported(self, plugin, target, httpx_mock):
        """A port that responds is reported as open."""
        # Ports probed: 80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9090, 9200, 27017
        # Ports 80 and 443 fail, 8080 responds, rest fail
        httpx_mock.add_exception(httpx.ConnectError("refused"))  # port 80
        httpx_mock.add_exception(httpx.ConnectError("refused"))  # port 443
        httpx_mock.add_response(
            url="http://example.com:8080/",
            status_code=200,
            headers={"server": "Apache/2.4"},
            text="OK",
        )
        # All remaining ports fail
        for _ in range(20):
            httpx_mock.add_exception(httpx.ConnectError("refused"))

        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert r.base_severity == Severity.INFO
        assert r.rule_id == "port_open"
        assert "8080" in r.title or "8080" in r.evidence

    # ------------------------------------------------------------------ #
    # Test 2: All ports refuse → empty
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_responses_were_requested=False)
    async def test_all_refused_empty(self, plugin, target, httpx_mock):
        """If all ports refuse connection, result is empty."""
        for _ in range(20):
            httpx_mock.add_exception(httpx.ConnectError("refused"))
        results = await plugin.run(target)
        assert results == []

    # ------------------------------------------------------------------ #
    # Test 3: Transport error → graceful skip
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_responses_were_requested=False)
    async def test_transport_error_graceful(self, plugin, target, httpx_mock):
        """TransportError during probing is silently skipped."""
        for _ in range(20):
            httpx_mock.add_exception(httpx.TimeoutException("timeout"))
        results = await plugin.run(target)
        assert results == []
