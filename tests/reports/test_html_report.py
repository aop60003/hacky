"""Tests for HTML report generator."""
from vibee_hacker.reports.html_report import HtmlReporter
from vibee_hacker.core.models import Result, Severity, Target


class TestHtmlReporter:
    def test_generate_report(self, tmp_path):
        results = [
            Result(
                plugin_name="sqli",
                base_severity=Severity.CRITICAL,
                title="SQL Injection",
                description="Found SQLi",
                cwe_id="CWE-89",
            ),
            Result(
                plugin_name="xss",
                base_severity=Severity.HIGH,
                title="XSS",
                description="Found XSS",
            ),
        ]
        target = Target(url="https://example.com")
        output = tmp_path / "report.html"
        HtmlReporter().generate(results, target, str(output))
        html = output.read_text()
        assert "VIBEE-Hacker Scan Report" in html
        assert "SQL Injection" in html
        assert "CWE-89" in html
        assert "example.com" in html
        assert "badge-critical" in html

    def test_empty_results(self, tmp_path):
        target = Target(url="https://example.com")
        output = tmp_path / "report.html"
        HtmlReporter().generate([], target, str(output))
        html = output.read_text()
        assert "Findings (0)" in html

    def test_severity_counts_displayed(self, tmp_path):
        results = [
            Result(plugin_name="p1", base_severity=Severity.HIGH, title="H1", description="d"),
            Result(plugin_name="p2", base_severity=Severity.HIGH, title="H2", description="d"),
            Result(plugin_name="p3", base_severity=Severity.LOW, title="L1", description="d"),
        ]
        target = Target(url="https://example.com")
        output = tmp_path / "report.html"
        HtmlReporter().generate(results, target, str(output))
        html = output.read_text()
        assert "Findings (3)" in html
        assert "badge-high" in html
        assert "badge-low" in html

    def test_dark_theme_css_present(self, tmp_path):
        target = Target(url="https://example.com")
        output = tmp_path / "report.html"
        HtmlReporter().generate([], target, str(output))
        html = output.read_text()
        # Dark theme background color
        assert "#1a1a2e" in html

    def test_whitebox_target_path(self, tmp_path):
        target = Target(path="/some/repo", mode="whitebox")
        output = tmp_path / "report.html"
        HtmlReporter().generate([], target, str(output))
        html = output.read_text()
        assert "/some/repo" in html
        assert "whitebox" in html

    def test_evidence_truncated(self, tmp_path):
        long_evidence = "A" * 200
        results = [
            Result(
                plugin_name="p",
                base_severity=Severity.MEDIUM,
                title="T",
                description="D",
                evidence=long_evidence,
            )
        ]
        target = Target(url="https://example.com")
        output = tmp_path / "report.html"
        HtmlReporter().generate(results, target, str(output))
        html = output.read_text()
        # Evidence is truncated to 120 chars in template
        assert "A" * 120 in html
        assert "A" * 200 not in html

    def test_all_severity_badges(self, tmp_path):
        results = [
            Result(plugin_name="p", base_severity=s, title="T", description="D")
            for s in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        ]
        target = Target(url="https://example.com")
        output = tmp_path / "report.html"
        HtmlReporter().generate(results, target, str(output))
        html = output.read_text()
        for badge in ["badge-critical", "badge-high", "badge-medium", "badge-low", "badge-info"]:
            assert badge in html
