"""Tests for AutofixEngine and FixSuggestion."""

from __future__ import annotations

import pytest

from vibee_hacker.core.autofix import AutofixEngine, FixSuggestion


class TestAutofix:
    @pytest.fixture
    def engine(self):
        return AutofixEngine()

    # --- test_get_fixes_sqli ---

    def test_get_fixes_sqli(self, engine):
        fixes = engine.get_fixes("sqli")
        assert len(fixes) >= 1
        assert all(f.rule_id == "sqli" for f in fixes)
        assert any("parameterized" in f.description.lower() for f in fixes)

    # --- test_get_fixes_xss ---

    def test_get_fixes_xss(self, engine):
        fixes = engine.get_fixes("xss")
        assert len(fixes) >= 1
        assert all(f.rule_id == "xss" for f in fixes)

    # --- test_get_fixes_language_filter ---

    def test_get_fixes_language_filter(self, engine):
        fixes_py = engine.get_fixes("sqli", language="python")
        assert all(f.language == "python" for f in fixes_py)
        assert len(fixes_py) >= 1

        fixes_js = engine.get_fixes("sqli", language="javascript")
        assert all(f.language == "javascript" for f in fixes_js)
        assert len(fixes_js) >= 1

    # --- test_get_fixes_unknown_rule ---

    def test_get_fixes_unknown_rule(self, engine):
        fixes = engine.get_fixes("nonexistent_rule_xyz")
        assert fixes == []

    # --- test_add_custom_fix ---

    def test_add_custom_fix(self, engine):
        custom = FixSuggestion(
            rule_id="my_custom_rule",
            language="python",
            description="Custom fix",
            before="bad_code()",
            after="good_code()",
            reference="https://example.com/fix",
        )
        engine.add_fix(custom)
        fixes = engine.get_fixes("my_custom_rule")
        assert len(fixes) == 1
        assert fixes[0].description == "Custom fix"
        assert fixes[0].reference == "https://example.com/fix"

    # --- test_supported_rules ---

    def test_supported_rules(self, engine):
        rules = engine.supported_rules
        assert isinstance(rules, list)
        assert "sqli" in rules
        assert "xss" in rules
        assert "cmdi" in rules
        assert "ssrf" in rules
        assert "hardcoded_secret" in rules

    # --- test_has_fix ---

    def test_has_fix(self, engine):
        assert engine.has_fix("sqli") is True
        assert engine.has_fix("xss") is True
        assert engine.has_fix("totally_unknown_rule") is False

    # --- test_prefix_match ---

    def test_prefix_match(self, engine):
        # "header_missing" is a prefix of "header_missing_csp"
        fixes = engine.get_fixes("header_missing")
        assert len(fixes) >= 1
        # "header_missing_csp" starts with "header_missing_csp" (exact match)
        fixes_exact = engine.get_fixes("header_missing_csp")
        assert len(fixes_exact) >= 1

    # --- test_fix_suggestion_fields ---

    def test_fix_suggestion_fields(self, engine):
        fixes = engine.get_fixes("sqli", language="python")
        assert len(fixes) >= 1
        fix = fixes[0]
        assert fix.rule_id == "sqli"
        assert fix.language == "python"
        assert fix.before != ""
        assert fix.after != ""
        assert isinstance(fix.description, str)
        assert fix.description != ""

    # --- test_empty_language_returns_all ---

    def test_empty_language_returns_all(self, engine):
        # sqli has both python and javascript fixes
        all_fixes = engine.get_fixes("sqli")
        py_fixes = engine.get_fixes("sqli", language="python")
        js_fixes = engine.get_fixes("sqli", language="javascript")
        assert len(all_fixes) == len(py_fixes) + len(js_fixes)
        assert len(all_fixes) >= 2

    # --- test_add_fix_appends_to_existing_rule ---

    def test_add_fix_appends_to_existing_rule(self, engine):
        original_count = len(engine.get_fixes("sqli"))
        extra = FixSuggestion(
            rule_id="sqli",
            language="java",
            description="Use PreparedStatement",
            before='stmt.execute("SELECT * FROM t WHERE id=" + id)',
            after='PreparedStatement ps = conn.prepareStatement("SELECT * FROM t WHERE id=?");\nps.setInt(1, id);',
        )
        engine.add_fix(extra)
        new_fixes = engine.get_fixes("sqli")
        assert len(new_fixes) == original_count + 1

    # --- test_has_fix_prefix ---

    def test_has_fix_prefix(self, engine):
        # "header_missing" is a prefix of "header_missing_csp" (or vice versa)
        assert engine.has_fix("header_missing") is True
        assert engine.has_fix("cors_wildcard") is True
