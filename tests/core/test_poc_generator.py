"""Tests for the PoC generator (TDD)."""

from __future__ import annotations

import pytest

from vibee_hacker.core.models import Result, Severity
from vibee_hacker.core.poc_generator import PoC, PoCGenerator, PLUGIN_TO_TYPE, POC_TEMPLATES


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_result(
    plugin_name: str,
    severity: Severity = Severity.HIGH,
    title: str = "Test Vulnerability",
    endpoint: str = "http://example.com/search",
    param: str = "q",
) -> Result:
    return Result(
        plugin_name=plugin_name,
        base_severity=severity,
        title=title,
        description="A test vulnerability description.",
        endpoint=endpoint,
        param_name=param,
    )


# ---------------------------------------------------------------------------
# PoC dataclass tests
# ---------------------------------------------------------------------------

def test_poc_to_dict():
    poc = PoC(
        vuln_title="SQL Injection",
        vuln_type="sqli",
        severity="HIGH",
        curl_command="curl -s 'http://example.com'",
        python_script="import httpx",
        raw_request="GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        description="desc",
        impact="impact",
        remediation="fix",
        verified=False,
    )
    d = poc.to_dict()
    assert d["vuln_title"] == "SQL Injection"
    assert d["vuln_type"] == "sqli"
    assert d["severity"] == "HIGH"
    assert d["curl_command"] == "curl -s 'http://example.com'"
    assert d["python_script"] == "import httpx"
    assert d["verified"] is False
    assert "description" in d
    assert "impact" in d
    assert "remediation" in d
    assert "raw_request" in d


def test_poc_to_markdown_contains_sections():
    poc = PoC(
        vuln_title="XSS",
        vuln_type="xss",
        severity="MEDIUM",
        curl_command="curl -s 'http://example.com'",
        python_script="print('hello')",
        raw_request="GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        description="XSS description",
        impact="Session hijacking",
        remediation="Encode output",
    )
    md = poc.to_markdown()
    assert "# PoC: XSS" in md
    assert "**Type:** xss" in md
    assert "**Severity:** MEDIUM" in md
    assert "## Description" in md
    assert "XSS description" in md
    assert "## Impact" in md
    assert "Session hijacking" in md
    assert "## Reproduce (curl)" in md
    assert "```bash" in md
    assert "## Exploit Script (Python)" in md
    assert "```python" in md
    assert "## Raw HTTP Request" in md
    assert "```http" in md
    assert "## Remediation" in md
    assert "Encode output" in md


def test_poc_to_markdown_omits_empty_sections():
    poc = PoC(
        vuln_title="Test",
        vuln_type="cors",
        severity="LOW",
        description="desc",
        impact="impact",
        remediation="fix",
        # No curl_command, python_script, raw_request
    )
    md = poc.to_markdown()
    assert "## Reproduce (curl)" not in md
    assert "## Exploit Script (Python)" not in md
    assert "## Raw HTTP Request" not in md
    assert "## Remediation" in md


# ---------------------------------------------------------------------------
# PoCGenerator.generate tests per vuln type
# ---------------------------------------------------------------------------

def test_generate_sqli_poc():
    gen = PoCGenerator()
    result = _make_result("sqli", Severity.HIGH, "SQL Injection Found")
    poc = gen.generate(result)
    assert poc is not None
    assert poc.vuln_type == "sqli"
    assert poc.severity == "HIGH"
    assert poc.vuln_title == "SQL Injection Found"
    assert "curl" in poc.curl_command
    assert "httpx" in poc.python_script
    assert "HTTP/1.1" in poc.raw_request
    assert poc.description != ""
    assert poc.impact != ""
    assert poc.remediation != ""


def test_generate_xss_poc():
    gen = PoCGenerator()
    result = _make_result("xss", Severity.MEDIUM, "Reflected XSS")
    poc = gen.generate(result)
    assert poc is not None
    assert poc.vuln_type == "xss"
    assert poc.severity == "MEDIUM"
    assert "<script>" in poc.curl_command or "xss" in poc.curl_command.lower() or "param" in poc.curl_command.lower() or poc.curl_command != ""
    assert "httpx" in poc.python_script
    assert "PAYLOAD" in poc.python_script


def test_generate_cmdi_poc():
    gen = PoCGenerator()
    result = _make_result("cmdi", Severity.CRITICAL, "Command Injection")
    poc = gen.generate(result)
    assert poc is not None
    assert poc.vuln_type == "cmdi"
    assert poc.severity == "CRITICAL"
    assert poc.curl_command != ""
    assert "uid=" in poc.python_script or "whoami" in poc.python_script or "httpx" in poc.python_script


def test_generate_ssrf_poc():
    gen = PoCGenerator()
    result = _make_result("ssrf", Severity.HIGH, "SSRF Detected")
    poc = gen.generate(result)
    assert poc is not None
    assert poc.vuln_type == "ssrf"
    assert "169.254.169.254" in poc.curl_command or "ssrf" in poc.curl_command.lower() or poc.curl_command != ""
    assert "httpx" in poc.python_script


def test_generate_idor_poc():
    gen = PoCGenerator()
    result = _make_result("idor_check", Severity.MEDIUM, "IDOR Found")
    poc = gen.generate(result)
    assert poc is not None
    assert poc.vuln_type == "idor"
    assert poc.curl_command != ""
    assert "httpx" in poc.python_script


def test_generate_cors_poc():
    gen = PoCGenerator()
    result = _make_result("cors_check", Severity.HIGH, "CORS Misconfiguration")
    poc = gen.generate(result)
    assert poc is not None
    assert poc.vuln_type == "cors"
    assert "evil.com" in poc.curl_command
    assert "ACAO" in poc.python_script or "Access-Control" in poc.python_script or "evil.com" in poc.python_script


def test_generate_open_redirect_poc():
    gen = PoCGenerator()
    result = _make_result("open_redirect", Severity.LOW, "Open Redirect")
    poc = gen.generate(result)
    assert poc is not None
    assert poc.vuln_type == "open_redirect"
    assert poc.severity == "LOW"
    assert "evil.com" in poc.python_script
    assert poc.curl_command != ""


def test_generate_default_creds_poc():
    gen = PoCGenerator()
    result = _make_result("default_creds", Severity.CRITICAL, "Default Credentials")
    poc = gen.generate(result)
    assert poc is not None
    assert poc.vuln_type == "default_creds"
    assert "admin" in poc.curl_command
    assert "admin" in poc.python_script


# ---------------------------------------------------------------------------
# Alias plugin mappings
# ---------------------------------------------------------------------------

def test_generate_ssti_maps_to_cmdi():
    gen = PoCGenerator()
    result = _make_result("ssti", Severity.HIGH, "SSTI Found")
    poc = gen.generate(result)
    assert poc is not None
    assert poc.vuln_type == "cmdi"


def test_generate_xxe_maps_to_ssrf():
    gen = PoCGenerator()
    result = _make_result("xxe", Severity.HIGH, "XXE Found")
    poc = gen.generate(result)
    assert poc is not None
    assert poc.vuln_type == "ssrf"


def test_generate_nosql_injection_maps_to_sqli():
    gen = PoCGenerator()
    result = _make_result("nosql_injection", Severity.MEDIUM, "NoSQL Injection")
    poc = gen.generate(result)
    assert poc is not None
    assert poc.vuln_type == "sqli"


def test_generate_path_traversal_maps_to_cmdi():
    gen = PoCGenerator()
    result = _make_result("path_traversal", Severity.HIGH, "Path Traversal")
    poc = gen.generate(result)
    assert poc is not None
    assert poc.vuln_type == "cmdi"


def test_generate_crlf_injection_maps_to_xss():
    gen = PoCGenerator()
    result = _make_result("crlf_injection", Severity.MEDIUM, "CRLF Injection")
    poc = gen.generate(result)
    assert poc is not None
    assert poc.vuln_type == "xss"


# ---------------------------------------------------------------------------
# Unsupported plugin type
# ---------------------------------------------------------------------------

def test_generate_unsupported_returns_none():
    gen = PoCGenerator()
    result = _make_result("some_unknown_plugin", Severity.INFO, "Unknown")
    poc = gen.generate(result)
    assert poc is None


def test_generate_empty_plugin_name_returns_none():
    gen = PoCGenerator()
    result = _make_result("", Severity.INFO, "Empty plugin")
    poc = gen.generate(result)
    assert poc is None


# ---------------------------------------------------------------------------
# generate_all
# ---------------------------------------------------------------------------

def test_generate_all_returns_pocs_for_supported():
    gen = PoCGenerator()
    results = [
        _make_result("sqli", Severity.HIGH, "SQLi"),
        _make_result("xss", Severity.MEDIUM, "XSS"),
        _make_result("some_unknown_plugin", Severity.INFO, "Unknown"),
    ]
    pocs = gen.generate_all(results)
    assert len(pocs) == 2
    types = {p.vuln_type for p in pocs}
    assert "sqli" in types
    assert "xss" in types


def test_generate_all_empty_list():
    gen = PoCGenerator()
    pocs = gen.generate_all([])
    assert pocs == []


def test_generate_all_all_unsupported():
    gen = PoCGenerator()
    results = [
        _make_result("unknown_a", Severity.HIGH, "A"),
        _make_result("unknown_b", Severity.LOW, "B"),
    ]
    pocs = gen.generate_all(results)
    assert pocs == []


# ---------------------------------------------------------------------------
# generate_report
# ---------------------------------------------------------------------------

def test_generate_report_markdown():
    gen = PoCGenerator()
    pocs = [
        PoC(vuln_title="SQLi", vuln_type="sqli", severity="HIGH",
            description="desc", impact="imp", remediation="fix",
            curl_command="curl ...", python_script="import httpx", raw_request="GET / HTTP/1.1\r\n\r\n"),
        PoC(vuln_title="XSS", vuln_type="xss", severity="MEDIUM",
            description="xss desc", impact="xss imp", remediation="xss fix",
            curl_command="curl ...", python_script="import httpx", raw_request="GET / HTTP/1.1\r\n\r\n"),
    ]
    report = gen.generate_report(pocs)
    assert "# VIBEE-Hacker — PoC Report" in report
    assert "**Total PoCs:** 2" in report
    assert "SQLi" in report
    assert "XSS" in report
    assert "1." in report
    assert "2." in report


def test_generate_report_empty():
    gen = PoCGenerator()
    report = gen.generate_report([])
    assert "No PoCs generated" in report
    assert "No exploitable vulnerabilities found" in report


# ---------------------------------------------------------------------------
# supported_types
# ---------------------------------------------------------------------------

def test_supported_types():
    gen = PoCGenerator()
    types = gen.supported_types
    assert isinstance(types, list)
    assert "sqli" in types
    assert "xss" in types
    assert "cmdi" in types
    assert "ssrf" in types
    assert "idor" in types
    assert "cors" in types
    assert "open_redirect" in types
    assert "default_creds" in types
    assert len(types) == len(POC_TEMPLATES)


# ---------------------------------------------------------------------------
# curl_command format
# ---------------------------------------------------------------------------

def test_curl_command_format_sqli():
    gen = PoCGenerator()
    result = _make_result("sqli", endpoint="http://example.com/search", param="q")
    poc = gen.generate(result)
    assert poc is not None
    # Curl must reference the endpoint URL
    assert "http://example.com/search" in poc.curl_command
    assert "q" in poc.curl_command


def test_curl_command_format_cors_uses_origin_header():
    gen = PoCGenerator()
    result = _make_result("cors_check", endpoint="http://api.example.com/data")
    poc = gen.generate(result)
    assert poc is not None
    assert "Origin" in poc.curl_command
    assert "evil.com" in poc.curl_command
    assert "http://api.example.com/data" in poc.curl_command


def test_curl_command_format_open_redirect_includes_param():
    gen = PoCGenerator()
    result = _make_result("open_redirect", endpoint="http://example.com/go", param="next")
    poc = gen.generate(result)
    assert poc is not None
    assert "next" in poc.curl_command


# ---------------------------------------------------------------------------
# raw_request structure
# ---------------------------------------------------------------------------

def test_raw_request_contains_host():
    gen = PoCGenerator()
    result = _make_result("sqli", endpoint="http://example.com/search?q=test")
    poc = gen.generate(result)
    assert poc is not None
    assert "Host: example.com" in poc.raw_request
    assert "HTTP/1.1" in poc.raw_request
    assert "User-Agent: VIBEE-Hacker" in poc.raw_request


def test_raw_request_path_with_query():
    gen = PoCGenerator()
    result = _make_result("xss", endpoint="http://example.com/page?search=hello")
    poc = gen.generate(result)
    assert poc is not None
    assert "/page?search=hello" in poc.raw_request


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

def test_severity_critical_mapped():
    gen = PoCGenerator()
    result = _make_result("sqli", severity=Severity.CRITICAL)
    poc = gen.generate(result)
    assert poc is not None
    assert poc.severity == "CRITICAL"


def test_severity_low_mapped():
    gen = PoCGenerator()
    result = _make_result("open_redirect", severity=Severity.LOW)
    poc = gen.generate(result)
    assert poc is not None
    assert poc.severity == "LOW"


def test_severity_info_mapped():
    gen = PoCGenerator()
    result = _make_result("cors_check", severity=Severity.INFO)
    poc = gen.generate(result)
    assert poc is not None
    assert poc.severity == "INFO"


# ---------------------------------------------------------------------------
# Python script interpolation
# ---------------------------------------------------------------------------

def test_python_script_contains_target_url():
    gen = PoCGenerator()
    result = _make_result("sqli", endpoint="http://target.local/api")
    poc = gen.generate(result)
    assert poc is not None
    assert "http://target.local/api" in poc.python_script


def test_python_script_contains_param():
    gen = PoCGenerator()
    result = _make_result("xss", endpoint="http://example.com/", param="search_term")
    poc = gen.generate(result)
    assert poc is not None
    assert "search_term" in poc.python_script
