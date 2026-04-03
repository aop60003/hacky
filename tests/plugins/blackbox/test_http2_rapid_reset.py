# tests/plugins/blackbox/test_http2_rapid_reset.py
"""Tests for HTTP/2 Rapid Reset DoS risk detection plugin."""
import pytest
import httpx
from unittest.mock import patch, MagicMock
from vibee_hacker.plugins.blackbox.http2_rapid_reset import Http2RapidResetPlugin
from vibee_hacker.core.models import Target, Severity


class TestHttp2RapidReset:
    @pytest.fixture
    def plugin(self):
        return Http2RapidResetPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/")

    @pytest.mark.asyncio
    async def test_http2_server_is_reported(self, plugin, target):
        """HTTP/2 server without mitigation headers — reported as MEDIUM."""
        with patch("vibee_hacker.plugins.blackbox.http2_rapid_reset.httpx.AsyncClient") as mock_client_class:
            mock_resp_obj = MagicMock()
            mock_resp_obj.http_version = "HTTP/2"
            mock_resp_obj.status_code = 200
            mock_resp_obj.headers = {}
            mock_client_class.return_value.__aenter__.return_value.get.return_value = mock_resp_obj

            results = await plugin.run(target)

        assert len(results) >= 1
        assert results[0].rule_id == "http2_rapid_reset_risk"
        assert results[0].cwe_id == "CWE-400"

    @pytest.mark.asyncio
    async def test_http1_server_not_reported(self, plugin, target):
        """HTTP/1.1 server — no results."""
        with patch("vibee_hacker.plugins.blackbox.http2_rapid_reset.httpx.AsyncClient") as mock_client_class:
            mock_resp_obj = MagicMock()
            mock_resp_obj.http_version = "HTTP/1.1"
            mock_resp_obj.status_code = 200
            mock_resp_obj.headers = {}
            mock_client_class.return_value.__aenter__.return_value.get.return_value = mock_resp_obj

            results = await plugin.run(target)

        assert results == []

    @pytest.mark.asyncio
    async def test_http_url_not_applicable(self, plugin):
        """HTTP (non-TLS) URL is not applicable."""
        target = Target(url="http://example.com/")
        assert plugin.is_applicable(target) is False

    @pytest.mark.asyncio
    async def test_https_url_is_applicable(self, plugin):
        """HTTPS URL is applicable."""
        target = Target(url="https://example.com/")
        assert plugin.is_applicable(target) is True

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin):
        """TransportError returns empty list."""
        target = Target(url="https://down.example.com/")
        with patch("vibee_hacker.plugins.blackbox.http2_rapid_reset.httpx.AsyncClient") as mock_client_class:
            mock_client_class.return_value.__aenter__.return_value.get.side_effect = httpx.ConnectError("refused")
            results = await plugin.run(target)
        assert results == []
