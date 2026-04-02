"""Tests for the YAML template engine."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest
import httpx

from vibee_hacker.core.template_engine import Template, TemplateEngine, SEVERITY_MAP
from vibee_hacker.core.models import Severity


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SQLI_YAML = textwrap.dedent("""\
    id: test-sqli
    info:
      name: Test SQL Injection
      severity: critical
      description: Detects SQL injection errors
      cwe: CWE-89
      tags:
        - sqli
        - injection
    requests:
      - method: GET
        path: "{{BaseURL}}"
        payloads:
          param_values:
            - "'"
            - "1 OR 1=1"
        matchers:
          - type: word
            words:
              - "SQL syntax"
              - "mysql_fetch"
            condition: or
          - type: status
            status:
              - 500
""")

HEADER_YAML = textwrap.dedent("""\
    id: test-header-check
    info:
      name: Security Header Check
      severity: low
      description: Looks for missing headers
      cwe: CWE-693
      tags: []
    requests:
      - method: GET
        path: "{{BaseURL}}"
        matchers:
          - type: header
            headers:
              X-Frame-Options: DENY
""")

REGEX_YAML = textwrap.dedent("""\
    id: test-regex
    info:
      name: Regex Pattern Test
      severity: medium
      description: Tests regex matcher
      cwe: ""
      tags: []
    requests:
      - method: GET
        path: "{{BaseURL}}"
        matchers:
          - type: regex
            regex:
              - "error\\\\s+in\\\\s+query"
              - "ORA-[0-9]+"
            condition: or
""")


# ---------------------------------------------------------------------------
# test_from_yaml
# ---------------------------------------------------------------------------

def test_from_yaml_basic():
    data = {
        "id": "my-plugin",
        "info": {
            "name": "My Plugin",
            "severity": "high",
            "description": "A test plugin",
            "cwe": "CWE-200",
            "tags": ["info", "disclosure"],
        },
        "requests": [],
    }
    t = Template.from_yaml(data)
    assert t.id == "my-plugin"
    assert t.name == "My Plugin"
    assert t.severity == Severity.HIGH
    assert t.description == "A test plugin"
    assert t.cwe == "CWE-200"
    assert t.tags == ["info", "disclosure"]
    assert t.requests == []


def test_from_yaml_defaults():
    """Missing fields should fall back to defaults."""
    t = Template.from_yaml({})
    assert t.id == "unknown"
    assert t.name == "Unknown"
    assert t.severity == Severity.INFO
    assert t.description == ""
    assert t.cwe == ""
    assert t.tags == []


# ---------------------------------------------------------------------------
# test_severity_mapping
# ---------------------------------------------------------------------------

def test_severity_mapping_all():
    pairs = [
        ("info", Severity.INFO),
        ("low", Severity.LOW),
        ("medium", Severity.MEDIUM),
        ("high", Severity.HIGH),
        ("critical", Severity.CRITICAL),
    ]
    for key, expected in pairs:
        assert SEVERITY_MAP[key] == expected


def test_severity_mapping_unknown_defaults_to_info():
    result = SEVERITY_MAP.get("nonexistent", Severity.INFO)
    assert result == Severity.INFO


# ---------------------------------------------------------------------------
# test_load_string
# ---------------------------------------------------------------------------

def test_load_string():
    engine = TemplateEngine()
    t = engine.load_string(SQLI_YAML)
    assert t.id == "test-sqli"
    assert t.severity == Severity.CRITICAL
    assert len(engine.templates) == 1


def test_load_string_appends_to_templates():
    engine = TemplateEngine()
    engine.load_string(SQLI_YAML)
    engine.load_string(HEADER_YAML)
    assert len(engine.templates) == 2
    assert engine.templates[0].id == "test-sqli"
    assert engine.templates[1].id == "test-header-check"


# ---------------------------------------------------------------------------
# test_load_file
# ---------------------------------------------------------------------------

def test_load_file(tmp_path):
    yaml_file = tmp_path / "mytemplate.yaml"
    yaml_file.write_text(SQLI_YAML)

    engine = TemplateEngine()
    t = engine.load_file(yaml_file)
    assert t.id == "test-sqli"
    assert len(engine.templates) == 1


def test_load_directory(tmp_path):
    (tmp_path / "a.yaml").write_text(SQLI_YAML)
    (tmp_path / "b.yaml").write_text(HEADER_YAML)
    (tmp_path / "not_yaml.txt").write_text("ignored")

    engine = TemplateEngine()
    count = engine.load_directory(tmp_path)
    assert count == 2
    assert len(engine.templates) == 2


def test_load_directory_nonexistent():
    engine = TemplateEngine()
    count = engine.load_directory(Path("/nonexistent/path"))
    assert count == 0


def test_load_directory_via_constructor(tmp_path):
    (tmp_path / "c.yaml").write_text(SQLI_YAML)
    engine = TemplateEngine(template_dir=tmp_path)
    assert len(engine.templates) == 1


# ---------------------------------------------------------------------------
# test_word_matcher_or
# ---------------------------------------------------------------------------

def test_word_matcher_or():
    engine = TemplateEngine()
    engine.load_string(SQLI_YAML)
    matcher = {"type": "word", "words": ["SQL syntax", "ORA-"], "condition": "or"}

    # Simulate a response containing one of the words
    resp = httpx.Response(500, text="You have an error in your SQL syntax near ...")
    assert engine._check_matcher(resp, matcher) is True

    resp_no_match = httpx.Response(200, text="Everything is fine")
    assert engine._check_matcher(resp_no_match, matcher) is False


# ---------------------------------------------------------------------------
# test_word_matcher_and
# ---------------------------------------------------------------------------

def test_word_matcher_and():
    engine = TemplateEngine()
    matcher = {"type": "word", "words": ["error", "query"], "condition": "and"}

    resp_both = httpx.Response(200, text="There was an error in the query")
    assert engine._check_matcher(resp_both, matcher) is True

    resp_one = httpx.Response(200, text="There was an error")
    assert engine._check_matcher(resp_one, matcher) is False


# ---------------------------------------------------------------------------
# test_status_matcher
# ---------------------------------------------------------------------------

def test_status_matcher_match():
    engine = TemplateEngine()
    matcher = {"type": "status", "status": [500, 502]}

    resp_500 = httpx.Response(500, text="Internal Server Error")
    assert engine._check_matcher(resp_500, matcher) is True

    resp_200 = httpx.Response(200, text="OK")
    assert engine._check_matcher(resp_200, matcher) is False


def test_status_matcher_empty_list():
    engine = TemplateEngine()
    matcher = {"type": "status", "status": []}
    resp = httpx.Response(500, text="error")
    assert engine._check_matcher(resp, matcher) is False


# ---------------------------------------------------------------------------
# test_regex_matcher
# ---------------------------------------------------------------------------

def test_regex_matcher_or():
    engine = TemplateEngine()
    matcher = {"type": "regex", "regex": ["ORA-[0-9]+", "mysql_error"], "condition": "or"}

    resp = httpx.Response(500, text="ORA-00942: table or view does not exist")
    assert engine._check_matcher(resp, matcher) is True

    resp_no = httpx.Response(200, text="all good")
    assert engine._check_matcher(resp_no, matcher) is False


def test_regex_matcher_and():
    engine = TemplateEngine()
    matcher = {"type": "regex", "regex": ["error", "query"], "condition": "and"}

    resp = httpx.Response(200, text="error in query execution")
    assert engine._check_matcher(resp, matcher) is True

    resp_partial = httpx.Response(200, text="error occurred")
    assert engine._check_matcher(resp_partial, matcher) is False


# ---------------------------------------------------------------------------
# test_execute_with_mock (httpx mock via pytest-httpx)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_execute_with_mock(httpx_mock):
    """Full execute() run: template detects SQLi in mocked response."""
    httpx_mock.add_response(
        url="http://target.test/?test='",
        status_code=500,
        text="You have an error in your SQL syntax near ...",
    )

    engine = TemplateEngine()
    engine.load_string(SQLI_YAML)

    results = await engine.execute("http://target.test/")
    assert len(results) == 1
    r = results[0]
    assert r.plugin_name == "template:test-sqli"
    assert r.base_severity == Severity.CRITICAL
    assert "'" in r.evidence
    assert r.cwe_id == "CWE-89"


# ---------------------------------------------------------------------------
# test_template_not_matched
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.httpx_mock(
    assert_all_requests_were_expected=False,
    assert_all_responses_were_requested=False,
)
async def test_template_not_matched(httpx_mock):
    """Template should produce no results when matchers don't fire."""
    # Respond to all requests with a clean 200 — no SQL error keywords
    httpx_mock.add_response(status_code=200, text="Welcome to our site")
    httpx_mock.add_response(status_code=200, text="Welcome to our site")
    httpx_mock.add_response(status_code=200, text="Welcome to our site")

    engine = TemplateEngine()
    engine.load_string(SQLI_YAML)

    results = await engine.execute("http://target.test/")
    assert results == []


# ---------------------------------------------------------------------------
# test_header_matcher
# ---------------------------------------------------------------------------

def test_header_matcher_present():
    engine = TemplateEngine()
    matcher = {"type": "header", "headers": {"X-Frame-Options": "DENY"}}

    resp = httpx.Response(200, headers={"X-Frame-Options": "DENY"}, text="ok")
    assert engine._check_matcher(resp, matcher) is True


def test_header_matcher_absent():
    engine = TemplateEngine()
    matcher = {"type": "header", "headers": {"X-Frame-Options": "DENY"}}

    resp = httpx.Response(200, text="no headers here")
    assert engine._check_matcher(resp, matcher) is False


# ---------------------------------------------------------------------------
# Integration: load built-in example template files
# ---------------------------------------------------------------------------

def test_example_sqli_yaml_loads():
    templates_dir = Path(__file__).parent.parent.parent / "vibee_hacker" / "templates"
    engine = TemplateEngine()
    t = engine.load_file(templates_dir / "example_sqli.yaml")
    assert t.id == "custom-sqli-error"
    assert t.severity == Severity.CRITICAL
    assert "sqli" in t.tags


def test_example_xss_yaml_loads():
    templates_dir = Path(__file__).parent.parent.parent / "vibee_hacker" / "templates"
    engine = TemplateEngine()
    t = engine.load_file(templates_dir / "example_xss.yaml")
    assert t.id == "custom-xss-reflect"
    assert t.severity == Severity.HIGH


def test_example_header_yaml_loads():
    templates_dir = Path(__file__).parent.parent.parent / "vibee_hacker" / "templates"
    engine = TemplateEngine()
    t = engine.load_file(templates_dir / "example_header.yaml")
    assert t.id == "missing-security-headers"
    assert t.severity == Severity.LOW
