"""Tests for AlertManager: grouping, filtering, deduplication."""

from __future__ import annotations

import pytest

from vibee_hacker.core.alert_manager import AlertGroup, AlertManager
from vibee_hacker.core.models import Result, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_result(
    plugin_name: str = "test_plugin",
    severity: Severity = Severity.MEDIUM,
    title: str = "Test",
    rule_id: str = "test_rule",
    endpoint: str = "",
    param_name: str | None = None,
    confidence: str = "firm",
    cwe_id: str | None = None,
) -> Result:
    return Result(
        plugin_name=plugin_name,
        base_severity=severity,
        title=title,
        description="Test description",
        rule_id=rule_id,
        endpoint=endpoint,
        param_name=param_name,
        confidence=confidence,
        cwe_id=cwe_id,
    )


# ---------------------------------------------------------------------------
# Construction tests
# ---------------------------------------------------------------------------

def test_empty_manager():
    mgr = AlertManager()
    assert mgr.count == 0
    assert mgr.results == []


def test_add_result():
    mgr = AlertManager()
    result = make_result()
    mgr.add(result)
    assert mgr.count == 1
    assert mgr.results[0] is result


def test_init_with_results():
    results = [make_result(severity=Severity.HIGH), make_result(severity=Severity.LOW)]
    mgr = AlertManager(results)
    assert mgr.count == 2


def test_results_property_returns_copy():
    """Mutating the returned list should not affect internal state."""
    mgr = AlertManager([make_result()])
    copy = mgr.results
    copy.clear()
    assert mgr.count == 1


# ---------------------------------------------------------------------------
# Filter tests
# ---------------------------------------------------------------------------

def test_filter_by_severity():
    mgr = AlertManager([
        make_result(severity=Severity.INFO),
        make_result(severity=Severity.LOW),
        make_result(severity=Severity.MEDIUM),
        make_result(severity=Severity.HIGH),
        make_result(severity=Severity.CRITICAL),
    ])
    high_plus = mgr.filter_by_severity("high")
    assert len(high_plus) == 2
    assert all(r.base_severity >= Severity.HIGH for r in high_plus)


def test_filter_by_severity_info_returns_all():
    mgr = AlertManager([make_result(severity=s) for s in Severity])
    assert len(mgr.filter_by_severity("info")) == len(list(Severity))


def test_filter_by_plugin():
    mgr = AlertManager([
        make_result(plugin_name="sqli"),
        make_result(plugin_name="xss"),
        make_result(plugin_name="sqli"),
    ])
    sqli = mgr.filter_by_plugin("sqli")
    assert len(sqli) == 2
    assert all(r.plugin_name == "sqli" for r in sqli)


def test_filter_by_confidence():
    mgr = AlertManager([
        make_result(confidence="firm"),
        make_result(confidence="tentative"),
        make_result(confidence="firm"),
    ])
    firm = mgr.filter_by_confidence("firm")
    assert len(firm) == 2


def test_exclude_rules():
    mgr = AlertManager([
        make_result(rule_id="sqli_basic"),
        make_result(rule_id="xss_reflected"),
        make_result(rule_id="info_leak"),
    ])
    filtered = mgr.exclude_rules(["sqli_basic", "info_leak"])
    assert len(filtered) == 1
    assert filtered[0].rule_id == "xss_reflected"


def test_exclude_rules_empty_list():
    mgr = AlertManager([make_result(rule_id="sqli"), make_result(rule_id="xss")])
    assert len(mgr.exclude_rules([])) == 2


# ---------------------------------------------------------------------------
# Group tests
# ---------------------------------------------------------------------------

def test_group_by_plugin():
    mgr = AlertManager([
        make_result(plugin_name="sqli", severity=Severity.HIGH),
        make_result(plugin_name="sqli", severity=Severity.MEDIUM),
        make_result(plugin_name="xss", severity=Severity.CRITICAL),
    ])
    groups = mgr.group_by_plugin()
    assert len(groups) == 2
    # xss has CRITICAL — should be first
    assert groups[0].key == "xss"
    assert groups[0].max_severity == Severity.CRITICAL
    assert groups[0].count == 1
    assert groups[1].key == "sqli"
    assert groups[1].count == 2


def test_group_by_severity():
    mgr = AlertManager([
        make_result(severity=Severity.CRITICAL),
        make_result(severity=Severity.HIGH),
        make_result(severity=Severity.HIGH),
        make_result(severity=Severity.INFO),
    ])
    groups = mgr.group_by_severity()
    assert len(groups) == 3
    # Sorted descending: CRITICAL, HIGH, INFO
    assert groups[0].max_severity == Severity.CRITICAL
    assert groups[0].count == 1
    assert groups[1].max_severity == Severity.HIGH
    assert groups[1].count == 2


def test_group_by_endpoint():
    mgr = AlertManager([
        make_result(endpoint="http://example.com/api/users", severity=Severity.CRITICAL),
        make_result(endpoint="http://example.com/api/users", severity=Severity.LOW),
        make_result(endpoint="http://example.com/login", severity=Severity.HIGH),
    ])
    groups = mgr.group_by_endpoint()
    assert len(groups) == 2
    # /api/users has CRITICAL — should be first
    assert groups[0].key == "/api/users"
    assert groups[0].count == 2
    assert groups[1].key == "/login"


def test_group_by_endpoint_no_endpoint():
    mgr = AlertManager([make_result(endpoint=""), make_result(endpoint="")])
    groups = mgr.group_by_endpoint()
    assert len(groups) == 1
    assert groups[0].key == "N/A"
    assert groups[0].count == 2


def test_group_by_cwe():
    mgr = AlertManager([
        make_result(cwe_id="CWE-89", severity=Severity.HIGH),
        make_result(cwe_id="CWE-89", severity=Severity.CRITICAL),
        make_result(cwe_id="CWE-79", severity=Severity.MEDIUM),
        make_result(cwe_id=None, severity=Severity.INFO),
    ])
    groups = mgr.group_by_cwe()
    assert len(groups) == 3
    cwe89 = next(g for g in groups if g.key == "CWE-89")
    assert cwe89.count == 2
    assert cwe89.max_severity == Severity.CRITICAL
    no_cwe = next(g for g in groups if g.key == "No CWE")
    assert no_cwe.count == 1


def test_group_labels():
    mgr = AlertManager([make_result(plugin_name="sqli")])
    groups = mgr.group_by_plugin()
    assert groups[0].label == "Plugin: sqli"


# ---------------------------------------------------------------------------
# Deduplicate tests
# ---------------------------------------------------------------------------

def test_deduplicate():
    mgr = AlertManager([
        make_result(rule_id="sqli", endpoint="http://example.com/", param_name="id"),
        make_result(rule_id="sqli", endpoint="http://example.com/", param_name="id"),  # duplicate
        make_result(rule_id="sqli", endpoint="http://example.com/", param_name="name"),  # diff param
        make_result(rule_id="xss", endpoint="http://example.com/", param_name="id"),   # diff rule
    ])
    deduped = mgr.deduplicate()
    assert len(deduped) == 3


def test_deduplicate_empty():
    mgr = AlertManager()
    assert mgr.deduplicate() == []


def test_deduplicate_preserves_order():
    results = [
        make_result(rule_id=f"rule_{i}", endpoint=f"http://example.com/{i}")
        for i in range(5)
    ]
    mgr = AlertManager(results)
    deduped = mgr.deduplicate()
    assert [r.rule_id for r in deduped] == [f"rule_{i}" for i in range(5)]


# ---------------------------------------------------------------------------
# Summary tests
# ---------------------------------------------------------------------------

def test_summary():
    mgr = AlertManager([
        make_result(plugin_name="sqli", severity=Severity.CRITICAL, rule_id="sqli_basic", endpoint="http://example.com/a"),
        make_result(plugin_name="sqli", severity=Severity.HIGH, rule_id="sqli_union", endpoint="http://example.com/b"),
        make_result(plugin_name="xss", severity=Severity.MEDIUM, rule_id="xss_reflected", endpoint="http://example.com/a"),
    ])
    s = mgr.summary()
    assert s["total"] == 3
    assert s["by_severity"][Severity.CRITICAL] == 1
    assert s["by_severity"][Severity.HIGH] == 1
    assert s["by_severity"][Severity.MEDIUM] == 1
    assert s["by_plugin"]["sqli"] == 2
    assert s["by_plugin"]["xss"] == 1
    assert s["unique_endpoints"] == 2
    assert s["unique_rules"] == 3


def test_summary_empty():
    mgr = AlertManager()
    s = mgr.summary()
    assert s["total"] == 0
    assert s["unique_endpoints"] == 0
    assert s["unique_rules"] == 0


# ---------------------------------------------------------------------------
# AlertGroup tests
# ---------------------------------------------------------------------------

def test_alert_group_count():
    group = AlertGroup(key="test", label="Test Group")
    assert group.count == 0
    group.results.append(make_result())
    assert group.count == 1
