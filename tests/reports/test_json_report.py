# tests/reports/test_json_report.py
import json
from vibee_hacker.reports.json_report import JsonReporter
from vibee_hacker.core.models import Result, Severity, Target


class TestJsonReporter:
    def test_generate_report(self, tmp_path):
        results = [
            Result(
                plugin_name="sqli",
                base_severity=Severity.CRITICAL,
                title="SQL Injection",
                description="Found SQLi",
                rule_id="sqli_error_based",
            )
        ]
        target = Target(url="https://example.com")
        output = tmp_path / "report.json"

        reporter = JsonReporter()
        reporter.generate(results, target, str(output))

        data = json.loads(output.read_text())
        assert data["target"] == "https://example.com"
        assert data["total_findings"] == 1
        assert data["findings"][0]["title"] == "SQL Injection"
        assert "scan_date" in data

    def test_empty_results(self, tmp_path):
        target = Target(url="https://example.com")
        output = tmp_path / "report.json"

        reporter = JsonReporter()
        reporter.generate([], target, str(output))

        data = json.loads(output.read_text())
        assert data["total_findings"] == 0
        assert data["findings"] == []
