# tests/plugins/blackbox/test_server_proto_pollution.py
"""Tests for ServerProtoPollutionPlugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.server_proto_pollution import ServerProtoPollutionPlugin
from vibee_hacker.core.models import Target, Severity


class TestServerProtoPollution:
    @pytest.fixture
    def plugin(self):
        return ServerProtoPollutionPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/api/data")

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_500_with_prototype_error_detected(self, plugin, target, httpx_mock):
        """500 error with prototype-related message is flagged as HIGH."""
        httpx_mock.add_response(
            status_code=500,
            text='{"error": "Cannot set property __proto__ of #<Object>"}',
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert r.base_severity == Severity.HIGH
        assert r.rule_id == "server_prototype_pollution"
        assert r.cwe_id == "CWE-1321"

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_reflected_payload_detected(self, plugin, target, httpx_mock):
        """Reflected vibee_pp_test in response body is flagged."""
        httpx_mock.add_response(
            status_code=200,
            text='{"polluted": "vibee_pp_test", "status": "ok"}',
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].rule_id == "server_prototype_pollution"

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False, assert_all_responses_were_requested=False)
    async def test_normal_responses_no_findings(self, plugin, target, httpx_mock):
        """Normal 200 JSON responses produce no results."""
        for _ in range(50):
            httpx_mock.add_response(
                status_code=200,
                text='{"status": "ok"}',
            )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_transport_error_returns_empty(self, plugin, target, httpx_mock):
        """Transport errors return empty results."""
        httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        assert results == []
