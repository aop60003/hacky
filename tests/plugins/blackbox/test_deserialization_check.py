# tests/plugins/blackbox/test_deserialization_check.py
"""Tests for insecure deserialization detection plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.deserialization_check import DeserializationCheckPlugin
from vibee_hacker.core.models import Target, Severity


class TestDeserializationCheck:
    @pytest.fixture
    def plugin(self):
        return DeserializationCheckPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/api/data")

    @pytest.mark.asyncio
    async def test_java_deserialization_error_detected(self, plugin, target, httpx_mock):
        """Java deserialization error in response triggers CRITICAL finding."""
        # Java probe returns error; plugin returns early before PHP probe
        httpx_mock.add_response(
            status_code=500,
            text="java.io.ObjectInputStream: ClassNotFoundException: com.evil.Payload",
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.CRITICAL
        assert results[0].rule_id == "deserialization_unsafe"
        assert results[0].cwe_id == "CWE-502"

    @pytest.mark.asyncio
    async def test_no_deserialization_error(self, plugin, target, httpx_mock):
        """No deserialization errors produces no results."""
        # 2 requests: Java probe + PHP probe
        httpx_mock.add_response(status_code=200, text="ok")
        httpx_mock.add_response(status_code=200, text="ok")
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, target, httpx_mock):
        """Transport error returns empty results gracefully."""
        httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        assert results == []
