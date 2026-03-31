# tests/plugins/blackbox/test_websocket_check.py
"""Tests for WebSocket origin validation check plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.websocket_check import WebsocketCheckPlugin
from vibee_hacker.core.models import Target, Severity


class TestWebsocketCheck:
    @pytest.fixture
    def plugin(self):
        return WebsocketCheckPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="http://example.com/")

    @pytest.mark.asyncio
    async def test_ws_upgrade_accepted_with_evil_origin(self, plugin, target, httpx_mock):
        """101 response with evil origin accepted is reported as HIGH."""
        # First request: probe for WebSocket support - accepted
        httpx_mock.add_response(
            url="http://example.com/",
            status_code=101,
            headers={"Upgrade": "websocket", "Connection": "Upgrade"},
            text="",
        )
        # Second request: evil origin probe - also accepted (101)
        httpx_mock.add_response(
            url="http://example.com/",
            status_code=101,
            headers={"Upgrade": "websocket", "Connection": "Upgrade"},
            text="",
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.HIGH
        assert results[0].rule_id == "websocket_no_origin_check"
        assert results[0].cwe_id == "CWE-346"

    @pytest.mark.asyncio
    async def test_upgrade_rejected_returns_empty(self, plugin, target, httpx_mock):
        """Non-101 response to upgrade request produces no results."""
        httpx_mock.add_response(
            url="http://example.com/",
            status_code=400,
            text="Bad Request",
        )
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, target, httpx_mock):
        """Transport error is handled gracefully."""
        httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        assert results == []
