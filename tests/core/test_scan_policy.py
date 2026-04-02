"""Tests for scan policy."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from vibee_hacker.core.scan_policy import ScanPolicy, BUILTIN_POLICIES


# ---------------------------------------------------------------------------
# test_default_policy
# ---------------------------------------------------------------------------

def test_default_policy_values():
    p = ScanPolicy()
    assert p.name == "default"
    assert p.description == ""
    assert p.enabled_plugins is None
    assert p.disabled_plugins == []
    assert p.enabled_categories is None
    assert p.disabled_categories == []
    assert p.enabled_phases is None
    assert p.min_severity == "info"
    assert p.max_requests_per_plugin == 100
    assert p.max_crawl_depth == 3
    assert p.max_crawl_pages == 50
    assert p.fuzz_params is True
    assert p.fuzz_headers is False
    assert p.fuzz_cookies is False
    assert p.max_payloads_per_param == 10


# ---------------------------------------------------------------------------
# test_plugin_enabled (all enabled by default)
# ---------------------------------------------------------------------------

def test_plugin_enabled_by_default():
    p = ScanPolicy()
    assert p.is_plugin_enabled("sqli") is True
    assert p.is_plugin_enabled("xss") is True
    assert p.is_plugin_enabled("anything") is True


def test_plugin_enabled_all_phases_by_default():
    p = ScanPolicy()
    assert p.is_plugin_enabled("sqli", plugin_phase=1) is True
    assert p.is_plugin_enabled("sqli", plugin_phase=5) is True


# ---------------------------------------------------------------------------
# test_plugin_disabled
# ---------------------------------------------------------------------------

def test_plugin_disabled_explicit():
    p = ScanPolicy(disabled_plugins=["sqli", "xss"])
    assert p.is_plugin_enabled("sqli") is False
    assert p.is_plugin_enabled("xss") is False
    assert p.is_plugin_enabled("cmdi") is True


def test_plugin_disabled_takes_priority_over_category_enable():
    """Explicit disable always wins, even if category is whitelisted."""
    p = ScanPolicy(
        enabled_categories=["injection"],
        disabled_plugins=["sqli"],
    )
    assert p.is_plugin_enabled("sqli", plugin_category="injection") is False
    assert p.is_plugin_enabled("xss", plugin_category="injection") is True


# ---------------------------------------------------------------------------
# test_category_filter
# ---------------------------------------------------------------------------

def test_category_enabled_whitelist():
    p = ScanPolicy(enabled_categories=["injection", "auth"])
    assert p.is_plugin_enabled("sqli", plugin_category="injection") is True
    assert p.is_plugin_enabled("brute_force", plugin_category="auth") is True
    assert p.is_plugin_enabled("misconfiguration", plugin_category="config") is False


def test_category_disabled():
    p = ScanPolicy(disabled_categories=["info"])
    assert p.is_plugin_enabled("banner_grab", plugin_category="info") is False
    assert p.is_plugin_enabled("sqli", plugin_category="injection") is True


def test_enabled_plugins_whitelist():
    p = ScanPolicy(enabled_plugins=["sqli", "cmdi"])
    assert p.is_plugin_enabled("sqli") is True
    assert p.is_plugin_enabled("cmdi") is True
    assert p.is_plugin_enabled("xss") is False
    assert p.is_plugin_enabled("ssrf") is False


# ---------------------------------------------------------------------------
# test_phase_filter
# ---------------------------------------------------------------------------

def test_phase_filter_whitelist():
    p = ScanPolicy(enabled_phases=[1, 2])
    assert p.is_plugin_enabled("sqli", plugin_phase=1) is True
    assert p.is_plugin_enabled("sqli", plugin_phase=2) is True
    assert p.is_plugin_enabled("sqli", plugin_phase=3) is False


def test_phase_filter_all_by_default():
    p = ScanPolicy()  # enabled_phases=None means all phases
    assert p.is_plugin_enabled("sqli", plugin_phase=99) is True


# ---------------------------------------------------------------------------
# test_from_dict
# ---------------------------------------------------------------------------

def test_from_dict_basic():
    data = {
        "name": "custom",
        "description": "My policy",
        "disabled_plugins": ["sqli"],
        "max_crawl_pages": 25,
        "fuzz_headers": True,
    }
    p = ScanPolicy.from_dict(data)
    assert p.name == "custom"
    assert p.description == "My policy"
    assert "sqli" in p.disabled_plugins
    assert p.max_crawl_pages == 25
    assert p.fuzz_headers is True


def test_from_dict_ignores_unknown_keys():
    data = {"name": "test", "unknown_key": "ignored", "max_crawl_pages": 5}
    p = ScanPolicy.from_dict(data)
    assert p.name == "test"
    assert p.max_crawl_pages == 5


# ---------------------------------------------------------------------------
# test_builtin_policies
# ---------------------------------------------------------------------------

def test_builtin_policies_exist():
    assert "default" in BUILTIN_POLICIES
    assert "quick" in BUILTIN_POLICIES
    assert "thorough" in BUILTIN_POLICIES
    assert "passive" in BUILTIN_POLICIES
    assert "injection-only" in BUILTIN_POLICIES


def test_quick_policy():
    p = BUILTIN_POLICIES["quick"]
    assert p.enabled_phases == [1, 2]
    assert p.max_crawl_pages == 10
    assert p.max_payloads_per_param == 3


def test_thorough_policy():
    p = BUILTIN_POLICIES["thorough"]
    assert p.max_crawl_depth == 5
    assert p.max_crawl_pages == 200
    assert p.fuzz_headers is True
    assert p.fuzz_cookies is True


def test_passive_policy():
    p = BUILTIN_POLICIES["passive"]
    assert p.fuzz_params is False
    assert p.enabled_phases == [1, 2]


def test_injection_only_policy():
    p = BUILTIN_POLICIES["injection-only"]
    assert p.enabled_plugins is not None
    assert "sqli" in p.enabled_plugins
    assert "xss" in p.enabled_plugins
    assert p.is_plugin_enabled("sqli") is True
    assert p.is_plugin_enabled("banner_grab") is False


# ---------------------------------------------------------------------------
# test_save_load_yaml
# ---------------------------------------------------------------------------

def test_save_load_yaml(tmp_path):
    policy = ScanPolicy(
        name="my-policy",
        description="Test policy",
        disabled_plugins=["sqli", "xss"],
        max_crawl_pages=20,
        fuzz_headers=True,
    )
    path = tmp_path / "policy.yaml"
    policy.save(path)

    assert path.exists()
    loaded = ScanPolicy.from_file(path)
    assert loaded.name == "my-policy"
    assert loaded.description == "Test policy"
    assert loaded.disabled_plugins == ["sqli", "xss"]
    assert loaded.max_crawl_pages == 20
    assert loaded.fuzz_headers is True


def test_save_load_json(tmp_path):
    policy = ScanPolicy(
        name="json-policy",
        enabled_phases=[1, 3],
        max_payloads_per_param=5,
    )
    path = tmp_path / "policy.json"
    policy.save(path)

    assert path.exists()
    loaded = ScanPolicy.from_file(path)
    assert loaded.name == "json-policy"
    assert loaded.enabled_phases == [1, 3]
    assert loaded.max_payloads_per_param == 5


def test_to_dict_roundtrip():
    policy = ScanPolicy(name="roundtrip", max_crawl_depth=7)
    d = policy.to_dict()
    assert d["name"] == "roundtrip"
    assert d["max_crawl_depth"] == 7
    restored = ScanPolicy.from_dict(d)
    assert restored.name == "roundtrip"
    assert restored.max_crawl_depth == 7


def test_from_file_yml_extension(tmp_path):
    data = {"name": "yml-test", "max_crawl_pages": 15}
    path = tmp_path / "policy.yml"
    path.write_text(yaml.dump(data))
    p = ScanPolicy.from_file(path)
    assert p.name == "yml-test"
    assert p.max_crawl_pages == 15
