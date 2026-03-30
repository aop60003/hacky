# tests/plugins/blackbox/test_prototype_pollution.py
"""Tests for prototype pollution detection plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.prototype_pollution import PrototypePollutionPlugin
from vibee_hacker.core.models import Target, Severity


class TestPrototypePollution:
    @pytest.fixture
    def plugin(self):
        return PrototypePollutionPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/api/data")

    @pytest.mark.asyncio
    async def test_500_error_after_proto_injection(self, plugin, target, httpx_mock):
        """500 error after __proto__ injection is reported as HIGH."""
        from vibee_hacker.plugins.blackbox.prototype_pollution import PAYLOADS
        # First payload causes a 500 error
        httpx_mock.add_response(
            url="https://example.com/api/data",
            status_code=500,
            text='{"error": "Internal server error: Cannot set property polluted of #<Object>"}',
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.HIGH
        assert results[0].rule_id == "prototype_pollution"
        assert results[0].cwe_id == "CWE-1321"

    @pytest.mark.asyncio
    async def test_normal_200_response(self, plugin, target, httpx_mock):
        """Normal 200 responses to all payloads produce no results."""
        from vibee_hacker.plugins.blackbox.prototype_pollution import PAYLOADS
        for _ in range(len(PAYLOADS)):
            httpx_mock.add_response(
                url="https://example.com/api/data",
                status_code=200,
                text='{"status": "ok"}',
            )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, target, httpx_mock):
        """Transport error returns empty results gracefully."""
        from vibee_hacker.plugins.blackbox.prototype_pollution import PAYLOADS
        for _ in range(len(PAYLOADS)):
            httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        assert results == []
