"""Tests for HTTP Request Smuggling detection plugin."""

from __future__ import annotations

import pytest
import httpx

from vibee_hacker.core.models import Target, Severity
from vibee_hacker.plugins.blackbox.http_smuggling import HttpSmugglingPlugin


@pytest.fixture
def plugin():
    return HttpSmugglingPlugin()


@pytest.fixture
def target():
    return Target(url="http://example.com")


# ---------------------------------------------------------------------------
# is_applicable
# ---------------------------------------------------------------------------

def test_is_applicable(plugin):
    assert plugin.is_applicable(Target(url="http://example.com")) is True


def test_not_applicable_no_url(plugin):
    assert plugin.is_applicable(Target(url=None, path="/code")) is False


# ---------------------------------------------------------------------------
# Ambiguous-header rejection (safe server)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ambiguous_headers_rejected(plugin, target, httpx_mock):
    """Server returning 400 to ambiguous CL+TE probe produces no smuggling results."""
    # POST with ambiguous headers → server rejects with 400
    httpx_mock.add_response(
        url="http://example.com",
        method="POST",
        status_code=400,
        text="Bad Request",
    )
    # GET for proxy detection check
    httpx_mock.add_response(
        url="http://example.com",
        method="GET",
        status_code=200,
        headers={"server": "nginx"},
        text="OK",
    )

    results = await plugin.run(target)
    # No smuggling results — server rejected the probe
    smuggling_results = [r for r in results if r.rule_id == "http_smuggling_te_cl"]
    assert smuggling_results == []


# ---------------------------------------------------------------------------
# Proxy detection
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_proxy_detected(plugin, target, httpx_mock):
    """nginx + x-forwarded-for header triggers LOW severity proxy finding."""
    # POST probe — server accepts (200), no timeout for timing probe
    httpx_mock.add_response(
        url="http://example.com",
        method="POST",
        status_code=200,
        text="OK",
    )
    # Second POST (timing probe) — also 200, no timeout
    httpx_mock.add_response(
        url="http://example.com",
        method="POST",
        status_code=200,
        text="OK",
    )
    # GET for proxy detection
    httpx_mock.add_response(
        url="http://example.com",
        method="GET",
        status_code=200,
        headers={
            "server": "nginx/1.21.0",
            "x-forwarded-for": "10.0.0.1",
        },
        text="OK",
    )

    results = await plugin.run(target)
    proxy_results = [r for r in results if r.rule_id == "http_smuggling_proxy_detected"]
    assert len(proxy_results) >= 1
    assert proxy_results[0].base_severity == Severity.LOW
    assert proxy_results[0].cwe_id == "CWE-444"


# ---------------------------------------------------------------------------
# Transport error resilience
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_transport_error_graceful(plugin, target, httpx_mock):
    """Transport errors on all requests are handled without raising exceptions."""
    httpx_mock.add_exception(httpx.ConnectError("connection refused"))
    httpx_mock.add_exception(httpx.ConnectError("connection refused"))

    results = await plugin.run(target)
    # Should not raise; may return empty or partial results
    assert isinstance(results, list)
