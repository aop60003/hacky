# tests/plugins/blackbox/test_snmp_check.py
"""Tests for SNMP management interface exposure plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.snmp_check import SnmpCheckPlugin
from vibee_hacker.core.models import Target, Severity


class TestSnmpCheck:
    @pytest.fixture
    def plugin(self):
        return SnmpCheckPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="http://example.com/")

    @pytest.mark.asyncio
    async def test_snmp_interface_found(self, plugin, target, httpx_mock):
        """SNMP management interface accessible is reported as HIGH."""
        from vibee_hacker.plugins.blackbox.snmp_check import SNMP_PATHS
        httpx_mock.add_response(
            url=f"http://example.com{SNMP_PATHS[0]}",
            status_code=200,
            text="SNMP community: public\nOID: 1.3.6.1.2.1.1.1",
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.HIGH
        assert results[0].rule_id == "snmp_interface_exposed"
        assert results[0].cwe_id == "CWE-200"

    @pytest.mark.asyncio
    async def test_all_404_returns_empty(self, plugin, target, httpx_mock):
        """All paths returning 404 produce no results."""
        from vibee_hacker.plugins.blackbox.snmp_check import SNMP_PATHS
        for _ in range(len(SNMP_PATHS)):
            httpx_mock.add_response(
                status_code=404,
                text="Not Found",
            )
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, target, httpx_mock):
        """Transport error is handled gracefully."""
        from vibee_hacker.plugins.blackbox.snmp_check import SNMP_PATHS
        for _ in range(len(SNMP_PATHS)):
            httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        assert results == []
