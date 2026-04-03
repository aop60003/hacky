# tests/plugins/blackbox/test_h2c_smuggling.py
"""Tests for H2cSmugglingPlugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.h2c_smuggling import H2cSmugglingPlugin
from vibee_hacker.core.models import Target, Severity


class TestH2cSmuggling:
    @pytest.fixture
    def plugin(self):
        return H2cSmugglingPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/")

    @pytest.mark.asyncio
    async def test_101_switching_protocols_detected(self, plugin, target, httpx_mock):
        """HTTP 101 Switching Protocols response is flagged as HIGH."""
        httpx_mock.add_response(
            status_code=101,
            headers={"Upgrade": "h2c", "Connection": "Upgrade"},
            text="",
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert r.base_severity == Severity.HIGH
        assert r.rule_id == "h2c_smuggling"
        assert r.cwe_id == "CWE-444"

    @pytest.mark.asyncio
    async def test_normal_200_no_findings(self, plugin, target, httpx_mock):
        """Normal 200 response without upgrade headers produces no results."""
        httpx_mock.add_response(
            status_code=200,
            headers={"Content-Type": "text/html"},
            text="<html><body>Hello</body></html>",
        )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, target, httpx_mock):
        """Transport error returns empty results."""
        httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        assert results == []
