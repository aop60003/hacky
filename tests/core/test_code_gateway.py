"""Tests for Secure Code Gateway (pre-commit hook scanner)."""
from __future__ import annotations

import pytest
from unittest.mock import patch, MagicMock

from vibee_hacker.core.code_gateway import CodeGateway, GatewayConfig, GatewayResult
from vibee_hacker.core.models import Result, Severity


# ── helpers ───────────────────────────────────────────────────────────────────

def _make_finding(severity: Severity, rule_id: str = "RULE-001") -> Result:
    return Result(
        plugin_name="test-plugin",
        base_severity=severity,
        title="Test finding",
        description="desc",
        rule_id=rule_id,
    )


# ── config ────────────────────────────────────────────────────────────────────

def test_config_defaults():
    cfg = GatewayConfig()
    assert cfg.fail_on_severity == "high"
    assert cfg.max_findings == 0
    assert cfg.exclude_rules == []
    assert "*.py" in cfg.include_patterns


# ── get_staged_files ──────────────────────────────────────────────────────────

def test_get_staged_files_empty(tmp_path):
    """Returns empty list when git reports nothing staged."""
    gw = CodeGateway()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="")
        files = gw.get_staged_files(str(tmp_path))
    assert files == []


def test_get_staged_files_filters_by_pattern():
    gw = CodeGateway(GatewayConfig(include_patterns=["*.py"]))
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=0, stdout="app.py\nREADME.md\nscript.js\n"
        )
        files = gw.get_staged_files(".")
    assert "app.py" in files
    assert "README.md" not in files
    assert "script.js" not in files


def test_include_patterns_js():
    gw = CodeGateway(GatewayConfig(include_patterns=["*.js"]))
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=0, stdout="index.js\nstyle.css\n"
        )
        files = gw.get_staged_files(".")
    assert files == ["index.js"]


# ── evaluate ──────────────────────────────────────────────────────────────────

def test_no_findings_pass():
    gw = CodeGateway()
    result = gw.evaluate([], staged_files=["app.py"])
    assert result.passed is True
    assert result.total_findings == 0
    assert result.blocking_findings == 0


def test_evaluate_pass_with_low_findings():
    """Low-severity findings should not block when threshold is HIGH."""
    gw = CodeGateway(GatewayConfig(fail_on_severity="high"))
    findings = [_make_finding(Severity.LOW), _make_finding(Severity.MEDIUM)]
    result = gw.evaluate(findings, staged_files=["app.py"])
    assert result.passed is True
    assert result.total_findings == 2
    assert result.blocking_findings == 0


def test_evaluate_fail_critical():
    gw = CodeGateway(GatewayConfig(fail_on_severity="high"))
    findings = [_make_finding(Severity.CRITICAL)]
    result = gw.evaluate(findings, staged_files=["app.py"])
    assert result.passed is False
    assert result.blocking_findings == 1


def test_evaluate_fail_max_findings():
    gw = CodeGateway(GatewayConfig(fail_on_severity="high", max_findings=2))
    findings = [_make_finding(Severity.LOW) for _ in range(3)]
    result = gw.evaluate(findings, staged_files=["app.py"])
    assert result.passed is False
    assert "Too many findings" in result.message


def test_exclude_rules():
    gw = CodeGateway(GatewayConfig(fail_on_severity="high", exclude_rules=["RULE-SKIP"]))
    findings = [
        _make_finding(Severity.CRITICAL, rule_id="RULE-SKIP"),
        _make_finding(Severity.LOW, rule_id="RULE-KEEP"),
    ]
    result = gw.evaluate(findings, staged_files=["app.py"])
    # CRITICAL is excluded, only LOW remains → should pass
    assert result.passed is True
    assert result.total_findings == 1


def test_gateway_result_fields():
    gw = CodeGateway()
    result = gw.evaluate([], staged_files=["x.py", "y.py"])
    assert isinstance(result, GatewayResult)
    assert result.staged_files == ["x.py", "y.py"]
    assert isinstance(result.message, str)
    assert isinstance(result.findings, list)


def test_mixed_severity():
    """Only HIGH+ should block; MEDIUM should not."""
    gw = CodeGateway(GatewayConfig(fail_on_severity="high"))
    findings = [
        _make_finding(Severity.MEDIUM),
        _make_finding(Severity.HIGH),
    ]
    result = gw.evaluate(findings, staged_files=["app.py"])
    assert result.passed is False
    assert result.blocking_findings == 1
    assert result.total_findings == 2
