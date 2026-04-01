"""Tests for SARIF report generator."""
from __future__ import annotations

import json
import os
import tempfile

import pytest

from vibee_hacker.core.models import Result, Severity, Target
from vibee_hacker.reports.sarif_report import SarifReporter


def make_result(**kwargs) -> Result:
    defaults = dict(
        plugin_name="test_plugin",
        base_severity=Severity.HIGH,
        title="Test Finding",
        description="A test vulnerability was found.",
        endpoint="src/app.py",
        rule_id="TEST001",
        cwe_id=None,
    )
    defaults.update(kwargs)
    return Result(**defaults)


class TestSarifReporter:
    def test_sarif_structure_valid(self, tmp_path):
        reporter = SarifReporter()
        target = Target(path="/some/project", mode="whitebox")
        results = [
            make_result(title="SQL Injection", rule_id="SQLI001", cwe_id="CWE-89"),
            make_result(
                title="XSS",
                rule_id="XSS001",
                base_severity=Severity.MEDIUM,
                cwe_id=None,
            ),
        ]
        out = str(tmp_path / "report.sarif")
        reporter.generate(results, target, out)

        with open(out, encoding="utf-8") as f:
            sarif = json.load(f)

        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert len(sarif["runs"]) == 1

        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "VIBEE-Hacker"
        from vibee_hacker import __version__
        assert run["tool"]["driver"]["version"] == __version__

        rules = run["tool"]["driver"]["rules"]
        assert len(rules) == 2
        rule_ids = [r["id"] for r in rules]
        assert "SQLI001" in rule_ids
        assert "XSS001" in rule_ids

        sarif_results = run["results"]
        assert len(sarif_results) == 2
        for sr in sarif_results:
            assert "ruleId" in sr
            assert "level" in sr
            assert "message" in sr
            assert "locations" in sr

    def test_empty_results(self, tmp_path):
        reporter = SarifReporter()
        target = Target(path="/some/project", mode="whitebox")
        out = str(tmp_path / "empty.sarif")
        reporter.generate([], target, out)

        with open(out, encoding="utf-8") as f:
            sarif = json.load(f)

        assert sarif["version"] == "2.1.0"
        run = sarif["runs"][0]
        assert run["tool"]["driver"]["rules"] == []
        assert run["results"] == []

    def test_cwe_in_rule_properties(self, tmp_path):
        reporter = SarifReporter()
        target = Target(path="/project", mode="whitebox")
        results = [
            make_result(rule_id="SQLI001", cwe_id="CWE-89", title="SQL Injection"),
        ]
        out = str(tmp_path / "cwe.sarif")
        reporter.generate(results, target, out)

        with open(out, encoding="utf-8") as f:
            sarif = json.load(f)

        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        rule = rules[0]
        assert "properties" in rule
        assert "CWE-89" in rule["properties"]["tags"]

    def test_no_cwe_omits_properties(self, tmp_path):
        reporter = SarifReporter()
        target = Target(path="/project", mode="whitebox")
        results = [make_result(rule_id="R001", cwe_id=None, title="Info Leak")]
        out = str(tmp_path / "no_cwe.sarif")
        reporter.generate(results, target, out)

        with open(out, encoding="utf-8") as f:
            sarif = json.load(f)

        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert "properties" not in rules[0]

    def test_severity_mapping(self, tmp_path):
        reporter = SarifReporter()
        target = Target(path="/project", mode="whitebox")
        results = [
            make_result(rule_id="C1", base_severity=Severity.CRITICAL, title="Critical"),
            make_result(rule_id="H1", base_severity=Severity.HIGH, title="High"),
            make_result(rule_id="M1", base_severity=Severity.MEDIUM, title="Medium"),
            make_result(rule_id="L1", base_severity=Severity.LOW, title="Low"),
            make_result(rule_id="I1", base_severity=Severity.INFO, title="Info"),
        ]
        out = str(tmp_path / "severity.sarif")
        reporter.generate(results, target, out)

        with open(out, encoding="utf-8") as f:
            sarif = json.load(f)

        sarif_results = sarif["runs"][0]["results"]
        levels = {r["ruleId"]: r["level"] for r in sarif_results}
        assert levels["C1"] == "error"
        assert levels["H1"] == "error"
        assert levels["M1"] == "warning"
        assert levels["L1"] == "note"
        assert levels["I1"] == "note"

    def test_deduplicates_rules(self, tmp_path):
        reporter = SarifReporter()
        target = Target(path="/project", mode="whitebox")
        results = [
            make_result(rule_id="SQLI001", title="SQL Injection"),
            make_result(rule_id="SQLI001", title="SQL Injection 2"),
        ]
        out = str(tmp_path / "dedup.sarif")
        reporter.generate(results, target, out)

        with open(out, encoding="utf-8") as f:
            sarif = json.load(f)

        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        assert sarif["runs"][0]["results"] is not None
        assert len(sarif["runs"][0]["results"]) == 2
