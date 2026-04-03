"""Tests for PoC auto-verifier (TDD — 15 tests)."""

from __future__ import annotations

import pytest
import httpx

from vibee_hacker.core.poc_generator import PoC
from vibee_hacker.core.poc_verifier import PoCVerifier, VerificationResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_poc(
    vuln_type: str = "sqli",
    curl_command: str = "curl -s 'http://example.com/search?q=test'",
    title: str = "SQL Injection",
) -> PoC:
    return PoC(
        vuln_title=title,
        vuln_type=vuln_type,
        severity="HIGH",
        curl_command=curl_command,
    )


# ---------------------------------------------------------------------------
# VerificationResult unit tests
# ---------------------------------------------------------------------------

def test_verification_result_defaults():
    """VerificationResult has correct default field values."""
    r = VerificationResult(poc_title="Test", verified=False, confidence="unconfirmed")
    assert r.poc_title == "Test"
    assert r.verified is False
    assert r.confidence == "unconfirmed"
    assert r.evidence == ""
    assert r.response_status == 0
    assert r.response_body_snippet == ""
    assert r.response_time_ms == 0.0
    assert r.error == ""


def test_verification_result_to_dict():
    """to_dict returns all expected keys with correct values."""
    r = VerificationResult(
        poc_title="XSS Test",
        verified=True,
        confidence="confirmed",
        evidence="payload reflected",
        response_status=200,
        response_body_snippet="<script>alert(1)</script>",
        response_time_ms=123.4,
        error="",
    )
    d = r.to_dict()
    assert d["poc_title"] == "XSS Test"
    assert d["verified"] is True
    assert d["confidence"] == "confirmed"
    assert d["evidence"] == "payload reflected"
    assert d["response_status"] == 200
    assert d["response_body_snippet"] == "<script>alert(1)</script>"
    assert d["response_time_ms"] == 123.4
    assert d["error"] == ""


# ---------------------------------------------------------------------------
# URL extraction tests
# ---------------------------------------------------------------------------

def test_extract_url_from_curl_single_quotes():
    """Extracts URL from curl command using single quotes."""
    verifier = PoCVerifier()
    url = verifier._extract_url_from_curl("curl -s 'http://example.com/path?q=1'")
    assert url == "http://example.com/path?q=1"


def test_extract_url_from_curl_double_quotes():
    """Extracts URL from curl command using double quotes."""
    verifier = PoCVerifier()
    url = verifier._extract_url_from_curl('curl -s "http://example.com/page"')
    assert url == "http://example.com/page"


def test_extract_url_empty_returns_empty():
    """Returns empty string when no URL can be found."""
    verifier = PoCVerifier()
    assert verifier._extract_url_from_curl("") == ""
    assert verifier._extract_url_from_curl("curl --help") == ""
    assert verifier._extract_url_from_curl("no curl here") == ""


# ---------------------------------------------------------------------------
# verify() — network tests via httpx_mock
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_verify_sqli_confirmed(httpx_mock):
    """SQLi PoC verified when response body contains SQL error pattern."""
    httpx_mock.add_response(
        url="http://example.com/search?q=test",
        method="GET",
        status_code=500,
        text="You have an error in your SQL syntax near '1'",
        headers={"content-type": "text/plain"},
    )
    verifier = PoCVerifier()
    poc = _make_poc(
        vuln_type="sqli",
        curl_command="curl -s 'http://example.com/search?q=test'",
        title="SQL Injection",
    )
    result = await verifier.verify(poc)
    assert result.verified is True
    assert result.confidence == "confirmed"
    assert "SQL syntax" in result.evidence
    assert result.response_status == 500


@pytest.mark.asyncio
async def test_verify_xss_reflected(httpx_mock):
    """XSS PoC verified when payload is reflected in response body."""
    httpx_mock.add_response(
        url="http://example.com/search?q=test",
        method="GET",
        status_code=200,
        text='<html><body><script>alert(1)</script></body></html>',
        headers={"content-type": "text/html"},
    )
    verifier = PoCVerifier()
    poc = _make_poc(
        vuln_type="xss",
        curl_command="curl -s 'http://example.com/search?q=test'",
        title="Reflected XSS",
    )
    result = await verifier.verify(poc)
    assert result.verified is True
    assert result.confidence == "confirmed"
    assert "XSS payload reflected" in result.evidence


@pytest.mark.asyncio
async def test_verify_cors_header(httpx_mock):
    """CORS PoC verified when ACAO header echoes the malicious origin."""
    httpx_mock.add_response(
        url="http://example.com/search?q=test",
        method="GET",
        status_code=200,
        text="OK",
        headers={"Access-Control-Allow-Origin": "https://evil.com"},
    )
    verifier = PoCVerifier()
    poc = _make_poc(
        vuln_type="cors",
        curl_command="curl -s 'http://example.com/search?q=test'",
        title="CORS Misconfiguration",
    )
    result = await verifier.verify(poc)
    assert result.verified is True
    assert result.confidence == "confirmed"
    assert "https://evil.com" in result.evidence


@pytest.mark.asyncio
async def test_verify_redirect(httpx_mock):
    """Open redirect PoC verified when Location header contains expected destination."""
    httpx_mock.add_response(
        url="http://example.com/search?q=test",
        method="GET",
        status_code=302,
        text="",
        headers={"Location": "https://evil.com/steal"},
    )
    verifier = PoCVerifier()
    poc = _make_poc(
        vuln_type="open_redirect",
        curl_command="curl -s 'http://example.com/search?q=test'",
        title="Open Redirect",
    )
    result = await verifier.verify(poc)
    assert result.verified is True
    assert result.confidence == "confirmed"
    assert "evil.com" in result.evidence


@pytest.mark.asyncio
async def test_verify_default_creds(httpx_mock):
    """Default creds PoC verified when response contains 'dashboard'."""
    httpx_mock.add_response(
        url="http://example.com/search?q=test",
        method="POST",
        status_code=200,
        text="Welcome to the dashboard! You are now logged in.",
        headers={"content-type": "text/html"},
    )
    verifier = PoCVerifier()
    poc = _make_poc(
        vuln_type="default_creds",
        curl_command="curl -s 'http://example.com/search?q=test'",
        title="Default Credentials",
    )
    result = await verifier.verify(poc)
    assert result.verified is True
    assert result.confidence == "confirmed"


@pytest.mark.asyncio
async def test_verify_not_confirmed(httpx_mock):
    """SQLi PoC not confirmed when response has no error patterns."""
    httpx_mock.add_response(
        url="http://example.com/search?q=test",
        method="GET",
        status_code=200,
        text="<html><body>Normal search results here</body></html>",
        headers={"content-type": "text/html"},
    )
    verifier = PoCVerifier()
    poc = _make_poc(
        vuln_type="sqli",
        curl_command="curl -s 'http://example.com/search?q=test'",
        title="SQL Injection",
    )
    result = await verifier.verify(poc)
    assert result.verified is False
    assert result.confidence == "unconfirmed"
    assert result.response_status == 200


@pytest.mark.asyncio
async def test_verify_transport_error(httpx_mock):
    """Transport error results in unconfirmed result with error message."""
    httpx_mock.add_exception(httpx.ConnectError("Connection refused"))
    verifier = PoCVerifier()
    poc = _make_poc(
        vuln_type="sqli",
        curl_command="curl -s 'http://example.com/search?q=test'",
        title="SQL Injection",
    )
    result = await verifier.verify(poc)
    assert result.verified is False
    assert result.confidence == "unconfirmed"
    assert "Connection error" in result.error


@pytest.mark.asyncio
async def test_verify_unknown_type():
    """Unknown vuln type returns unconfirmed without making network requests."""
    verifier = PoCVerifier()
    poc = _make_poc(
        vuln_type="unknown_type_xyz",
        curl_command="curl -s 'http://example.com/'",
        title="Unknown",
    )
    result = await verifier.verify(poc)
    assert result.verified is False
    assert result.confidence == "unconfirmed"
    assert "unknown_type_xyz" in result.error


@pytest.mark.asyncio
async def test_verify_all(httpx_mock):
    """verify_all processes a list of PoCs and returns a result for each."""
    # Two PoCs: sqli gets a SQL error, xss gets a clean response
    httpx_mock.add_response(
        url="http://example.com/sqli",
        method="GET",
        status_code=500,
        text="SQL syntax error near '1'",
        headers={"content-type": "text/plain"},
    )
    httpx_mock.add_response(
        url="http://example.com/xss",
        method="GET",
        status_code=200,
        text="clean response",
        headers={"content-type": "text/html"},
    )

    verifier = PoCVerifier()
    pocs = [
        PoC(
            vuln_title="SQL Injection",
            vuln_type="sqli",
            severity="HIGH",
            curl_command="curl -s 'http://example.com/sqli'",
        ),
        PoC(
            vuln_title="XSS",
            vuln_type="xss",
            severity="MEDIUM",
            curl_command="curl -s 'http://example.com/xss'",
        ),
    ]
    results = await verifier.verify_all(pocs)
    assert len(results) == 2
    assert results[0].verified is True
    assert results[1].verified is False


# ---------------------------------------------------------------------------
# summary()
# ---------------------------------------------------------------------------

def test_summary():
    """summary() returns correct counts and verification_rate."""
    verifier = PoCVerifier()
    results = [
        VerificationResult(poc_title="A", verified=True, confidence="confirmed"),
        VerificationResult(poc_title="B", verified=True, confidence="confirmed"),
        VerificationResult(poc_title="C", verified=False, confidence="unconfirmed"),
        VerificationResult(poc_title="D", verified=False, confidence="false_positive"),
        VerificationResult(poc_title="E", verified=False, confidence="likely"),
    ]
    s = verifier.summary(results)
    assert s["total"] == 5
    assert s["confirmed"] == 2
    assert s["likely"] == 1
    assert s["unconfirmed"] == 1
    assert s["false_positive"] == 1
    assert s["verification_rate"] == "2/5"

    # Empty list
    empty_s = verifier.summary([])
    assert empty_s["total"] == 0
    assert empty_s["verification_rate"] == "0/0"
