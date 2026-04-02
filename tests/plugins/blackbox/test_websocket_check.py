"""Tests for WebSocket security scanner plugin."""

from __future__ import annotations

import pytest
import httpx

from vibee_hacker.core.models import Target, Severity
from vibee_hacker.plugins.blackbox.websocket_check import WebsocketCheckPlugin


@pytest.fixture
def plugin():
    return WebsocketCheckPlugin()


@pytest.fixture
def target():
    return Target(url="http://example.com")


# ---------------------------------------------------------------------------
# is_applicable
# ---------------------------------------------------------------------------

def test_is_applicable(plugin):
    assert plugin.is_applicable(Target(url="http://example.com")) is True
    assert plugin.is_applicable(Target(url=None, path="/some/path")) is False


# ---------------------------------------------------------------------------
# Page scanning
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ws_url_in_page(plugin, target, httpx_mock):
    """ws:// URL in page source is discovered and reported."""
    # Main page with embedded ws:// URL
    httpx_mock.add_response(
        url="http://example.com",
        status_code=200,
        text='<script>var sock = new WebSocket("ws://example.com/ws");</script>',
    )
    # Probe requests for WS_PATHS — all 404
    httpx_mock.add_response(status_code=404, text="not found")
    httpx_mock.add_response(status_code=404, text="not found")
    httpx_mock.add_response(status_code=404, text="not found")
    httpx_mock.add_response(status_code=404, text="not found")
    httpx_mock.add_response(status_code=404, text="not found")
    httpx_mock.add_response(status_code=404, text="not found")
    httpx_mock.add_response(status_code=404, text="not found")

    results = await plugin.run(target)
    rule_ids = {r.rule_id for r in results}
    assert "ws_endpoint_found" in rule_ids


@pytest.mark.asyncio
async def test_socketio_detected(plugin, target, httpx_mock):
    """socket.io reference in page triggers INFO result."""
    httpx_mock.add_response(
        url="http://example.com",
        status_code=200,
        text='<script src="/socket.io/socket.io.js"></script>',
    )
    # Probe requests
    for _ in range(7):
        httpx_mock.add_response(status_code=404, text="not found")

    results = await plugin.run(target)
    rule_ids = {r.rule_id for r in results}
    assert "ws_socketio_detected" in rule_ids
    socketio_results = [r for r in results if r.rule_id == "ws_socketio_detected"]
    assert socketio_results[0].base_severity == Severity.INFO


@pytest.mark.asyncio
async def test_unencrypted_ws(plugin, target, httpx_mock):
    """ws:// (unencrypted) endpoint triggers MEDIUM severity result."""
    httpx_mock.add_response(
        url="http://example.com",
        status_code=200,
        text='<script>var s = new WebSocket("ws://example.com/stream");</script>',
    )
    for _ in range(7):
        httpx_mock.add_response(status_code=404, text="not found")

    results = await plugin.run(target)
    unencrypted = [r for r in results if r.rule_id == "ws_unencrypted"]
    assert len(unencrypted) >= 1
    assert unencrypted[0].base_severity == Severity.MEDIUM
    assert unencrypted[0].cwe_id == "CWE-319"


@pytest.mark.asyncio
async def test_no_ws_found(plugin, target, httpx_mock):
    """Clean page with no WebSocket references returns no findings."""
    httpx_mock.add_response(
        url="http://example.com",
        status_code=200,
        text="<html><body><p>Hello world</p></body></html>",
    )
    for _ in range(7):
        httpx_mock.add_response(status_code=404, text="not found")

    results = await plugin.run(target)
    assert results == []


# ---------------------------------------------------------------------------
# No-URL target
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_no_url_returns_empty(plugin):
    """Target without URL returns empty list immediately."""
    t = Target(url=None, path="/some/dir")
    results = await plugin.run(t)
    assert results == []
