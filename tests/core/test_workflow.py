"""Tests for workflow chaining engine."""

from __future__ import annotations

import pytest

from vibee_hacker.core.models import Result, Severity
from vibee_hacker.core.workflow import (
    BUILTIN_RULES,
    WorkflowCondition,
    WorkflowEngine,
    WorkflowRule,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_result(
    plugin_name: str = "test_plugin",
    rule_id: str = "test_rule",
    title: str = "Test Title",
    severity: Severity = Severity.MEDIUM,
) -> Result:
    return Result(
        plugin_name=plugin_name,
        base_severity=severity,
        title=title,
        description="Test description",
        rule_id=rule_id,
    )


# ---------------------------------------------------------------------------
# WorkflowCondition tests
# ---------------------------------------------------------------------------

def test_condition_matches_plugin():
    cond = WorkflowCondition(plugin_name="sqli")
    result = make_result(plugin_name="sqli")
    assert cond.matches(result) is True


def test_condition_matches_plugin_regex():
    cond = WorkflowCondition(plugin_name="sql.*")
    result = make_result(plugin_name="sqli_scanner")
    assert cond.matches(result) is True


def test_condition_matches_rule_id():
    cond = WorkflowCondition(rule_id="dir_enum")
    result = make_result(rule_id="dir_enum_wp_config")
    assert cond.matches(result) is True


def test_condition_matches_title():
    cond = WorkflowCondition(title_contains="WordPress")
    result = make_result(title="WordPress 6.4 detected")
    assert cond.matches(result) is True


def test_condition_matches_title_case_insensitive():
    cond = WorkflowCondition(title_contains="wordpress")
    result = make_result(title="WordPress 6.4 detected")
    assert cond.matches(result) is True


def test_condition_matches_severity():
    cond = WorkflowCondition(min_severity="high")
    result_high = make_result(severity=Severity.HIGH)
    result_critical = make_result(severity=Severity.CRITICAL)
    result_medium = make_result(severity=Severity.MEDIUM)
    assert cond.matches(result_high) is True
    assert cond.matches(result_critical) is True
    assert cond.matches(result_medium) is False


def test_condition_no_match_plugin():
    cond = WorkflowCondition(plugin_name="xss")
    result = make_result(plugin_name="sqli")
    assert cond.matches(result) is False


def test_condition_no_match_title():
    cond = WorkflowCondition(title_contains="WordPress")
    result = make_result(title="Joomla CMS detected")
    assert cond.matches(result) is False


def test_condition_no_match_severity():
    cond = WorkflowCondition(min_severity="critical")
    result = make_result(severity=Severity.HIGH)
    assert cond.matches(result) is False


def test_condition_empty_matches_all():
    """An empty WorkflowCondition matches any result."""
    cond = WorkflowCondition()
    result = make_result()
    assert cond.matches(result) is True


# ---------------------------------------------------------------------------
# WorkflowRule tests
# ---------------------------------------------------------------------------

def test_workflow_rule_and_logic():
    """AND logic: both conditions must match."""
    rule = WorkflowRule(
        id="test_and",
        name="Test AND Rule",
        description="Both conditions must match",
        conditions=[
            WorkflowCondition(plugin_name="sqli"),
            WorkflowCondition(plugin_name="debug_detection"),
        ],
        output_severity="critical",
        logic="and",
    )
    results = [
        make_result(plugin_name="sqli"),
        make_result(plugin_name="debug_detection"),
    ]
    finding = rule.evaluate(results)
    assert finding is not None
    assert finding.plugin_name == "workflow"
    assert finding.base_severity == Severity.CRITICAL
    assert finding.rule_id == "workflow_test_and"


def test_workflow_rule_and_logic_partial_no_trigger():
    """AND logic: only one condition matched should not trigger."""
    rule = WorkflowRule(
        id="test_and_partial",
        name="Test AND Partial",
        description="Both conditions must match",
        conditions=[
            WorkflowCondition(plugin_name="sqli"),
            WorkflowCondition(plugin_name="debug_detection"),
        ],
        logic="and",
    )
    results = [make_result(plugin_name="sqli")]
    finding = rule.evaluate(results)
    assert finding is None


def test_workflow_rule_or_logic():
    """OR logic: any one condition must match."""
    rule = WorkflowRule(
        id="test_or",
        name="Test OR Rule",
        description="Any condition must match",
        conditions=[
            WorkflowCondition(plugin_name="sqli"),
            WorkflowCondition(plugin_name="xss"),
        ],
        output_severity="high",
        logic="or",
    )
    # Only xss result present — should still trigger
    results = [make_result(plugin_name="xss")]
    finding = rule.evaluate(results)
    assert finding is not None
    assert finding.base_severity == Severity.HIGH


def test_workflow_rule_or_logic_no_match():
    """OR logic: no conditions matched should not trigger."""
    rule = WorkflowRule(
        id="test_or_none",
        name="Test OR None",
        description="Any condition must match",
        conditions=[
            WorkflowCondition(plugin_name="sqli"),
            WorkflowCondition(plugin_name="xss"),
        ],
        logic="or",
    )
    results = [make_result(plugin_name="cors")]
    finding = rule.evaluate(results)
    assert finding is None


def test_workflow_rule_not_triggered():
    """Rule with unmatched conditions returns None."""
    rule = WorkflowRule(
        id="test_no_trigger",
        name="No Trigger",
        description="Should not trigger",
        conditions=[
            WorkflowCondition(plugin_name="nonexistent_plugin"),
        ],
        logic="and",
    )
    results = [make_result(plugin_name="sqli")]
    assert rule.evaluate(results) is None


def test_workflow_rule_output_title():
    """Custom output_title is used when provided."""
    rule = WorkflowRule(
        id="test_title",
        name="Rule Name",
        description="Desc",
        conditions=[WorkflowCondition(plugin_name="sqli")],
        output_title="Custom Alert Title",
    )
    results = [make_result(plugin_name="sqli")]
    finding = rule.evaluate(results)
    assert finding is not None
    assert finding.title == "Custom Alert Title"


def test_workflow_rule_name_as_fallback_title():
    """Rule name is used as title when output_title is empty."""
    rule = WorkflowRule(
        id="test_name_title",
        name="Fallback Name Title",
        description="Desc",
        conditions=[WorkflowCondition(plugin_name="sqli")],
        output_title="",
    )
    results = [make_result(plugin_name="sqli")]
    finding = rule.evaluate(results)
    assert finding is not None
    assert finding.title == "Fallback Name Title"


# ---------------------------------------------------------------------------
# WorkflowEngine tests
# ---------------------------------------------------------------------------

def test_workflow_engine_evaluate():
    engine = WorkflowEngine()
    rule = WorkflowRule(
        id="engine_test",
        name="Engine Test Rule",
        description="Test",
        conditions=[WorkflowCondition(plugin_name="sqli")],
        output_severity="high",
    )
    engine.add_rule(rule)
    results = [make_result(plugin_name="sqli")]
    findings = engine.evaluate(results)
    assert len(findings) == 1
    assert findings[0].rule_id == "workflow_engine_test"


def test_workflow_engine_no_match_returns_empty():
    engine = WorkflowEngine()
    rule = WorkflowRule(
        id="no_match",
        name="No Match",
        description="Test",
        conditions=[WorkflowCondition(plugin_name="nonexistent")],
    )
    engine.add_rule(rule)
    results = [make_result(plugin_name="sqli")]
    assert engine.evaluate(results) == []


def test_workflow_engine_multiple_rules():
    engine = WorkflowEngine()
    for i in range(3):
        engine.add_rule(WorkflowRule(
            id=f"rule_{i}",
            name=f"Rule {i}",
            description="Test",
            conditions=[WorkflowCondition(plugin_name=f"plugin_{i}")],
        ))
    results = [
        make_result(plugin_name="plugin_0"),
        make_result(plugin_name="plugin_2"),
    ]
    findings = engine.evaluate(results)
    assert len(findings) == 2


# ---------------------------------------------------------------------------
# Builtin rules tests
# ---------------------------------------------------------------------------

def test_builtin_rules_count():
    """Verify at least 5 built-in rules are defined."""
    assert len(BUILTIN_RULES) >= 5


def test_workflow_wp_config_rule():
    """WordPress + dir_enum should trigger wp_config_exposed rule."""
    engine = WorkflowEngine()
    engine.load_builtin_rules()

    results = [
        make_result(plugin_name="tech_fingerprint", title="WordPress 6.4 Detected"),
        make_result(plugin_name="dir_enum", rule_id="dir_enum_wp_config", title="File exposed"),
    ]
    findings = engine.evaluate(results)
    rule_ids = [f.rule_id for f in findings]
    assert "workflow_wp_config_exposed" in rule_ids


def test_workflow_sqli_debug_rule():
    """SQLi + debug_detection should trigger sqli_plus_debug rule."""
    engine = WorkflowEngine()
    engine.load_builtin_rules()

    results = [
        make_result(plugin_name="sqli", title="SQL Injection"),
        make_result(plugin_name="debug_detection", title="Debug mode enabled"),
    ]
    findings = engine.evaluate(results)
    rule_ids = [f.rule_id for f in findings]
    assert "workflow_sqli_plus_debug" in rule_ids


def test_workflow_xss_no_csp_rule():
    """XSS + missing CSP header should trigger xss_plus_no_csp rule."""
    engine = WorkflowEngine()
    engine.load_builtin_rules()

    results = [
        make_result(plugin_name="xss", title="XSS found"),
        make_result(plugin_name="header_check", rule_id="csp_analysis", title="No CSP"),
    ]
    findings = engine.evaluate(results)
    rule_ids = [f.rule_id for f in findings]
    assert "workflow_xss_plus_no_csp" in rule_ids


def test_builtin_rules_all_have_conditions():
    """All built-in rules must have at least one condition."""
    for rule in BUILTIN_RULES:
        assert len(rule.conditions) >= 1, f"Rule {rule.id} has no conditions"


def test_builtin_rules_unique_ids():
    """All built-in rules must have unique IDs."""
    ids = [r.id for r in BUILTIN_RULES]
    assert len(ids) == len(set(ids))
