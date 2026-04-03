"""Tests for race condition detection plugin."""

from __future__ import annotations

import pytest
import httpx

from vibee_hacker.plugins.blackbox.race_condition import RaceConditionPlugin
from vibee_hacker.core.models import Target, Severity


@pytest.fixture
def plugin():
    return RaceConditionPlugin()


@pytest.fixture
def target():
    return Target(url="http://example.com/api/order")


# ---------------------------------------------------------------------------
# is_applicable
# ---------------------------------------------------------------------------

def test_is_applicable(plugin):
    """Plugin is applicable when target has a URL."""
    assert plugin.is_applicable(Target(url="http://example.com")) is True


def test_not_applicable_no_url(plugin):
    """Plugin is not applicable when target has no URL."""
    assert plugin.is_applicable(Target(url=None, path="/some/code")) is False


# ---------------------------------------------------------------------------
# Consistent responses — no finding
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_consistent_responses_no_finding(plugin, target, httpx_mock):
    """All identical responses (baseline + 10 burst) produce no findings."""
    # baseline + 10 concurrent
    for _ in range(11):
        httpx_mock.add_response(
            url="http://example.com/api/order",
            method="GET",
            status_code=200,
            text="OK same response",
            headers={"content-type": "text/plain"},
        )
    results = await plugin.run(target)
    assert results == []


# ---------------------------------------------------------------------------
# Status code inconsistency → HIGH finding
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_inconsistent_status_detected(plugin, target, httpx_mock):
    """Mixed 200/500 responses under concurrent load trigger HIGH finding."""
    # Baseline: 200
    httpx_mock.add_response(
        url="http://example.com/api/order",
        method="GET",
        status_code=200,
        text="OK",
    )
    # Burst: 7 x 200, 3 x 500
    for _ in range(7):
        httpx_mock.add_response(
            url="http://example.com/api/order",
            method="GET",
            status_code=200,
            text="OK",
        )
    for _ in range(3):
        httpx_mock.add_response(
            url="http://example.com/api/order",
            method="GET",
            status_code=500,
            text="Internal Server Error",
        )
    results = await plugin.run(target)
    assert len(results) >= 1
    race_result = results[0]
    assert race_result.base_severity == Severity.HIGH
    assert race_result.rule_id == "race_condition_status_inconsistency"
    assert race_result.cwe_id == "CWE-362"


# ---------------------------------------------------------------------------
# Response length variance > 20% → MEDIUM finding
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_length_variance_detected(plugin, target, httpx_mock):
    """Response length variance >20% under concurrent load triggers MEDIUM finding."""
    # Baseline: 200 with 100-byte body
    httpx_mock.add_response(
        url="http://example.com/api/order",
        method="GET",
        status_code=200,
        text="A" * 100,
    )
    # Burst: 9 responses of 100 bytes, 1 response of 2000 bytes (>20% variance)
    for _ in range(9):
        httpx_mock.add_response(
            url="http://example.com/api/order",
            method="GET",
            status_code=200,
            text="A" * 100,
        )
    httpx_mock.add_response(
        url="http://example.com/api/order",
        method="GET",
        status_code=200,
        text="B" * 2000,
    )
    results = await plugin.run(target)
    assert len(results) >= 1
    race_result = results[0]
    assert race_result.base_severity == Severity.MEDIUM
    assert race_result.rule_id == "race_condition_length_variance"
    assert race_result.cwe_id == "CWE-362"


# ---------------------------------------------------------------------------
# Transport error on baseline → graceful return
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_transport_error_graceful(plugin, target, httpx_mock):
    """Transport error on baseline request returns empty results gracefully."""
    httpx_mock.add_exception(httpx.ConnectError("Connection refused"))
    results = await plugin.run(target)
    assert results == []


# ---------------------------------------------------------------------------
# Max results limit
# ---------------------------------------------------------------------------

@pytest.mark.httpx_mock(assert_all_responses_were_requested=False)
@pytest.mark.asyncio
async def test_max_results_limit(plugin, httpx_mock):
    """Plugin returns at most 5 results even with many URLs in context."""
    from vibee_hacker.core.models import InterPhaseContext

    base_url = "http://example.com"
    extra_urls = [f"http://example.com/path{i}" for i in range(10)]

    target = Target(url=base_url)
    context = InterPhaseContext()
    # Patch crawl_urls onto context
    object.__setattr__(context, "__dict__", {**context.__dict__, "crawl_urls": extra_urls})

    # For each URL: baseline (200) + 10 burst responses with mixed statuses
    all_urls = [base_url] + extra_urls[:5]
    for url in all_urls:
        # baseline
        httpx_mock.add_response(url=url, method="GET", status_code=200, text="OK")
        # 10 burst: mix 200/500 to trigger finding
        for _ in range(7):
            httpx_mock.add_response(url=url, method="GET", status_code=200, text="OK")
        for _ in range(3):
            httpx_mock.add_response(url=url, method="GET", status_code=500, text="Error")

    results = await plugin.run(target, context)
    assert len(results) <= 5


# ---------------------------------------------------------------------------
# No URL returns empty
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_no_url_returns_empty(plugin):
    """Plugin returns empty list when target has no URL."""
    target = Target(url=None, path="/some/code")
    results = await plugin.run(target)
    assert results == []
