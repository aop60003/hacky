"""Tests for the Request Repeater module."""

from __future__ import annotations

import pytest
import httpx
from pytest_httpx import HTTPXMock

from vibee_hacker.core.repeater import (
    Repeater,
    RepeaterHistoryEntry,
    RepeaterRequest,
    RepeaterResponse,
)


# ---------------------------------------------------------------------------
# Dataclass default tests
# ---------------------------------------------------------------------------

def test_repeater_request_defaults():
    req = RepeaterRequest()
    assert req.method == "GET"
    assert req.url == ""
    assert req.headers == {}
    assert req.body == ""
    assert req.cookies == {}


def test_repeater_response_defaults():
    resp = RepeaterResponse()
    assert resp.status_code == 0
    assert resp.headers == {}
    assert resp.body == ""
    assert resp.elapsed_ms == 0.0
    assert resp.content_length == 0
    assert resp.timestamp is not None


# ---------------------------------------------------------------------------
# send() tests using pytest-httpx
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_send_get(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        method="GET",
        url="http://example.com/",
        status_code=200,
        text="Hello World",
        headers={"content-type": "text/html"},
    )

    repeater = Repeater()
    req = RepeaterRequest(method="GET", url="http://example.com/")
    resp = await repeater.send(req, label="test_get")

    assert resp.status_code == 200
    assert "Hello World" in resp.body
    assert resp.content_length == len(b"Hello World")


@pytest.mark.asyncio
async def test_send_post(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        method="POST",
        url="http://example.com/api",
        status_code=201,
        json={"created": True},
    )

    repeater = Repeater()
    req = RepeaterRequest(
        method="POST",
        url="http://example.com/api",
        headers={"Content-Type": "application/json"},
        body='{"key": "value"}',
    )
    resp = await repeater.send(req)

    assert resp.status_code == 201
    assert "created" in resp.body


@pytest.mark.asyncio
async def test_send_with_cookies(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        method="GET",
        url="http://example.com/protected",
        status_code=200,
        text="Authenticated",
    )

    repeater = Repeater()
    req = RepeaterRequest(
        method="GET",
        url="http://example.com/protected",
        cookies={"session": "abc123"},
    )
    resp = await repeater.send(req)
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# History tracking tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_history_tracking(httpx_mock: HTTPXMock):
    httpx_mock.add_response(status_code=200, text="resp1")
    httpx_mock.add_response(status_code=404, text="not found")

    repeater = Repeater()
    req1 = RepeaterRequest(url="http://example.com/a")
    req2 = RepeaterRequest(url="http://example.com/b")
    await repeater.send(req1, label="first")
    await repeater.send(req2, label="second")

    history = repeater.get_history()
    assert len(history) == 2
    assert history[0].label == "first"
    assert history[1].label == "second"
    assert history[0].response.status_code == 200
    assert history[1].response.status_code == 404


@pytest.mark.asyncio
async def test_history_limit(httpx_mock: HTTPXMock):
    for _ in range(5):
        httpx_mock.add_response(status_code=200, text="ok")

    repeater = Repeater()
    for i in range(5):
        await repeater.send(RepeaterRequest(url=f"http://example.com/{i}"))

    limited = repeater.get_history(limit=3)
    assert len(limited) == 3


def test_clear_history():
    repeater = Repeater()
    # Manually add entries to history without network calls
    entry = RepeaterHistoryEntry(
        request=RepeaterRequest(url="http://example.com/"),
        response=RepeaterResponse(status_code=200),
        label="test",
    )
    repeater.history.append(entry)
    assert len(repeater.history) == 1

    repeater.clear_history()
    assert len(repeater.history) == 0


# ---------------------------------------------------------------------------
# diff_responses test
# ---------------------------------------------------------------------------

def test_diff_responses():
    repeater = Repeater()

    r1 = RepeaterResponse(status_code=200, content_length=100, elapsed_ms=50.0, body="Hello")
    r2 = RepeaterResponse(status_code=404, content_length=50, elapsed_ms=30.0, body="Not Found")

    repeater.history.append(RepeaterHistoryEntry(
        request=RepeaterRequest(url="http://example.com/"),
        response=r1,
    ))
    repeater.history.append(RepeaterHistoryEntry(
        request=RepeaterRequest(url="http://example.com/missing"),
        response=r2,
    ))

    diff = repeater.diff_responses(0, 1)
    assert diff["status_diff"] is True
    assert diff["status"] == (200, 404)
    assert diff["length_diff"] == 50
    assert diff["lengths"] == (100, 50)
    assert diff["time_diff_ms"] == pytest.approx(20.0)


def test_diff_responses_same():
    repeater = Repeater()

    r = RepeaterResponse(status_code=200, content_length=100, elapsed_ms=10.0)
    for _ in range(2):
        repeater.history.append(RepeaterHistoryEntry(
            request=RepeaterRequest(url="http://example.com/"),
            response=r,
        ))

    diff = repeater.diff_responses(0, 1)
    assert diff["status_diff"] is False
    assert diff["length_diff"] == 0


def test_diff_responses_out_of_range():
    repeater = Repeater()
    diff = repeater.diff_responses(0, 1)
    assert "error" in diff
    assert diff["error"] == "Index out of range"


# ---------------------------------------------------------------------------
# Transport error test
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_transport_error(httpx_mock: HTTPXMock):
    httpx_mock.add_exception(httpx.ConnectError("Connection refused"))

    repeater = Repeater()
    req = RepeaterRequest(method="GET", url="http://unreachable.example.com/")
    resp = await repeater.send(req)

    assert resp.status_code == 0
    assert "Error:" in resp.body
    # Error entry still goes into history
    assert len(repeater.history) == 1
