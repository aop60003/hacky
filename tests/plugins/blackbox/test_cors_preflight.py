# tests/plugins/blackbox/test_cors_preflight.py
"""Tests for CORS Preflight Bypass detection plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.cors_preflight import CorsPreflightPlugin, EVIL_ORIGIN
from vibee_hacker.core.models import Target, Severity


class TestCorsPreflight:
    @pytest.fixture
    def plugin(self):
        return CorsPreflightPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://api.example.com/data")

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_evil_origin_with_credentials_is_critical(self, plugin, target, httpx_mock):
        """ACAO reflects evil origin + ACAC: true — CRITICAL finding."""
        httpx_mock.add_response(
            status_code=200,
            text='{"user": "admin"}',
            headers={
                "Access-Control-Allow-Origin": EVIL_ORIGIN,
                "Access-Control-Allow-Credentials": "true",
            },
            is_reusable=True,
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].rule_id == "cors_preflight_bypass"
        assert results[0].cwe_id == "CWE-346"
        assert results[0].base_severity == Severity.CRITICAL

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_evil_origin_without_credentials_is_high(self, plugin, target, httpx_mock):
        """ACAO reflects evil origin without credentials — HIGH finding."""
        httpx_mock.add_response(
            status_code=200,
            text='{"data": "public"}',
            headers={"Access-Control-Allow-Origin": EVIL_ORIGIN},
            is_reusable=True,
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].rule_id == "cors_preflight_bypass"
        assert results[0].base_severity == Severity.HIGH

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_no_cors_headers_not_vulnerable(self, plugin, target, httpx_mock):
        """No CORS headers in response — no results."""
        httpx_mock.add_response(
            status_code=200,
            text='{"data": "value"}',
            is_reusable=True,
        )
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, httpx_mock):
        """TransportError returns empty list."""
        target = Target(url="https://down.example.com/api")
        httpx_mock.add_exception(httpx.ConnectError("connection refused"), is_reusable=True)
        results = await plugin.run(target)
        assert results == []
