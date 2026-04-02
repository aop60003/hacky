"""Tests for InteractshClient — no real network calls."""

from __future__ import annotations

import pytest
import httpx
from datetime import timezone

from vibee_hacker.core.interactsh_client import InteractshClient, InteractshEvent


class TestInteractshClient:
    def test_init_defaults(self):
        """Client initialises with default server and no token."""
        client = InteractshClient()
        assert client.server == InteractshClient.DEFAULT_SERVER
        assert client.token is None
        assert client._registered is False
        assert client._interactions == []
        assert len(client._correlation_id) == 20  # secrets.token_hex(10)

    def test_init_custom(self):
        """Custom server and token are stored."""
        client = InteractshClient(server="interactsh.com", token="mytoken")
        assert client.server == "interactsh.com"
        assert client.token == "mytoken"

    def test_base_domain(self):
        """base_domain combines correlation_id and server."""
        client = InteractshClient(server="oast.pro")
        assert client.base_domain == f"{client._correlation_id}.oast.pro"

    def test_generate_payload(self):
        """generate_payload returns a subdomain under base_domain."""
        client = InteractshClient(server="oast.pro")
        payload = client.generate_payload()
        assert payload.endswith(f".{client.base_domain}")
        # unique prefix is 8 hex chars (token_hex(4))
        prefix = payload.split(".")[0]
        assert len(prefix) == 8

    def test_generate_payload_with_tag(self):
        """generate_payload with tag includes tag in subdomain."""
        client = InteractshClient(server="oast.pro")
        payload = client.generate_payload(tag="ssrf")
        # Format: <unique>-ssrf.<correlation_id>.oast.pro
        parts = payload.split(".")
        assert "ssrf" in parts[0]
        assert payload.endswith(f".{client.base_domain}")

    def test_generate_url(self):
        """generate_url wraps payload in a full URL."""
        client = InteractshClient(server="oast.pro")
        url = client.generate_url(tag="xss", protocol="http")
        assert url.startswith("http://")
        assert "xss" in url
        assert client._correlation_id in url

    def test_generate_url_default_protocol(self):
        """generate_url defaults to https."""
        client = InteractshClient()
        url = client.generate_url()
        assert url.startswith("https://")

    def test_has_interactions_false_initially(self):
        """has_interactions is False before any events."""
        client = InteractshClient()
        assert client.has_interactions is False

    def test_has_interactions(self):
        """has_interactions becomes True after an event is added."""
        client = InteractshClient()
        from datetime import datetime
        event = InteractshEvent(
            unique_id="abc123",
            full_id="abc123.correlation.oast.pro",
            raw_request="GET / HTTP/1.1",
            remote_address="1.2.3.4",
            timestamp=datetime.now(timezone.utc),
            protocol="http",
        )
        client._interactions.append(event)
        assert client.has_interactions is True

    def test_find_by_tag(self):
        """find_by_tag returns events whose unique_id or full_id contain the tag."""
        client = InteractshClient()
        from datetime import datetime
        ev1 = InteractshEvent(
            unique_id="abc-ssrf",
            full_id="abc-ssrf.corr.oast.pro",
            raw_request="",
            remote_address="",
            timestamp=datetime.now(timezone.utc),
            protocol="http",
        )
        ev2 = InteractshEvent(
            unique_id="xyz-xss",
            full_id="xyz-xss.corr.oast.pro",
            raw_request="",
            remote_address="",
            timestamp=datetime.now(timezone.utc),
            protocol="http",
        )
        client._interactions.extend([ev1, ev2])

        ssrf_results = client.find_by_tag("ssrf")
        assert len(ssrf_results) == 1
        assert ssrf_results[0].unique_id == "abc-ssrf"

        xss_results = client.find_by_tag("xss")
        assert len(xss_results) == 1
        assert xss_results[0].unique_id == "xyz-xss"

        empty = client.find_by_tag("notexist")
        assert empty == []

    @pytest.mark.asyncio
    async def test_register_failure_graceful(self, httpx_mock):
        """register() returns False gracefully on network failure."""
        httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        client = InteractshClient(server="oast.pro")
        result = await client.register()
        assert result is False
        assert client._registered is False

    @pytest.mark.asyncio
    async def test_register_success(self, httpx_mock):
        """register() returns True and sets _registered on HTTP 200."""
        client = InteractshClient(server="oast.pro")
        httpx_mock.add_response(
            url=f"https://oast.pro/register?correlationId={client._correlation_id}",
            status_code=200,
            text="ok",
        )
        result = await client.register()
        assert result is True
        assert client._registered is True

    @pytest.mark.asyncio
    async def test_poll_returns_empty_when_not_registered(self):
        """poll() returns [] without any HTTP call if not registered."""
        client = InteractshClient()
        events = await client.poll()
        assert events == []

    @pytest.mark.asyncio
    async def test_poll_parses_events(self, httpx_mock):
        """poll() parses returned interaction items into InteractshEvent objects."""
        client = InteractshClient(server="oast.pro")
        client._registered = True
        httpx_mock.add_response(
            url=f"https://oast.pro/poll?correlationId={client._correlation_id}",
            status_code=200,
            json={
                "data": [
                    {
                        "unique-id": "abc123",
                        "full-id": "abc123.corr.oast.pro",
                        "raw-request": "GET / HTTP/1.1\r\n\r\n",
                        "remote-address": "10.0.0.1",
                        "protocol": "http",
                    }
                ]
            },
        )
        events = await client.poll()
        assert len(events) == 1
        assert events[0].unique_id == "abc123"
        assert events[0].protocol == "http"
        assert client.has_interactions is True

    @pytest.mark.asyncio
    async def test_deregister(self, httpx_mock):
        """deregister() sets _registered to False and returns True on 200."""
        client = InteractshClient(server="oast.pro")
        client._registered = True
        httpx_mock.add_response(
            url=f"https://oast.pro/deregister?correlationId={client._correlation_id}",
            status_code=200,
            text="ok",
        )
        result = await client.deregister()
        assert result is True
        assert client._registered is False
