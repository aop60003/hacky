"""Tests for CVSS v3.1 base score calculator."""

from __future__ import annotations

import pytest

from vibee_hacker.core.cvss import CVSSCalculator, CVSSVector, VULN_CVSS_MAP


class TestCVSSVector:
    # --- vector_string ---

    def test_vector_string_format(self):
        v = CVSSVector()
        s = v.to_vector_string()
        assert s.startswith("CVSS:3.1/")
        assert "AV:" in s
        assert "AC:" in s
        assert "PR:" in s
        assert "UI:" in s
        assert "S:" in s
        assert "C:" in s
        assert "I:" in s
        assert "A:" in s

    def test_vector_string_values(self):
        v = CVSSVector(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="H",
            integrity="H",
            availability="H",
        )
        s = v.to_vector_string()
        assert "AV:N" in s
        assert "AC:L" in s
        assert "PR:N" in s
        assert "UI:N" in s
        assert "S:U" in s
        assert "C:H" in s
        assert "I:H" in s
        assert "A:H" in s

    # --- calculate_score: known values ---

    def test_score_sqli_is_critical(self):
        """SQLi vector should score 9.8 (critical)."""
        v = CVSSVector(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="H",
            integrity="H",
            availability="H",
        )
        score = v.calculate_score()
        assert abs(score - 9.8) < 0.15, f"Expected ~9.8, got {score}"

    def test_score_xss_is_medium(self):
        """XSS vector should score 6.1 (medium)."""
        v = CVSSVector(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="R",
            scope="C",
            confidentiality="L",
            integrity="L",
            availability="N",
        )
        score = v.calculate_score()
        assert abs(score - 6.1) < 0.15, f"Expected ~6.1, got {score}"

    def test_zero_impact_score_is_zero(self):
        """All None impact metrics gives score 0.0."""
        v = CVSSVector(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="N",
            integrity="N",
            availability="N",
        )
        score = v.calculate_score()
        assert score == 0.0

    def test_max_score_is_ten(self):
        """Maximum possible CVSS score is 10.0."""
        v = CVSSVector(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="C",
            confidentiality="H",
            integrity="H",
            availability="H",
        )
        score = v.calculate_score()
        assert score <= 10.0
        assert score >= 9.0  # Should be 10.0

    def test_custom_vector_score_is_float(self):
        """Score always returns a float."""
        v = CVSSVector(
            attack_vector="L",
            attack_complexity="H",
            privileges_required="L",
            user_interaction="R",
            scope="U",
            confidentiality="L",
            integrity="N",
            availability="N",
        )
        score = v.calculate_score()
        assert isinstance(score, float)
        assert 0.0 <= score <= 10.0


class TestCVSSCalculator:
    @pytest.fixture
    def calc(self):
        return CVSSCalculator()

    # --- score_for_rule ---

    def test_score_sqli(self, calc):
        score = calc.score_for_rule("sqli")
        assert score is not None
        assert score >= 9.0  # Should be ~9.8

    def test_score_xss(self, calc):
        score = calc.score_for_rule("xss")
        assert score is not None
        assert 5.0 <= score <= 7.5  # Should be ~6.1

    def test_score_unknown_returns_none(self, calc):
        score = calc.score_for_rule("totally_unknown_vuln_xyz")
        assert score is None

    # --- vector_for_rule ---

    def test_vector_for_rule_sqli(self, calc):
        v = calc.vector_for_rule("sqli")
        assert v is not None
        assert isinstance(v, CVSSVector)

    def test_vector_for_rule_unknown_returns_none(self, calc):
        v = calc.vector_for_rule("totally_unknown_vuln_xyz")
        assert v is None

    # --- calculate ---

    def test_calculate_matches_vector_method(self, calc):
        v = CVSSVector(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="H",
            integrity="H",
            availability="H",
        )
        assert calc.calculate(v) == v.calculate_score()

    # --- supported_rules ---

    def test_supported_rules_contains_expected(self, calc):
        rules = calc.supported_rules()
        assert "sqli" in rules
        assert "xss" in rules
        assert "ssrf" in rules

    # --- none_impact ---

    def test_none_impact_score(self, calc):
        v = CVSSVector(
            confidentiality="N",
            integrity="N",
            availability="N",
        )
        score = calc.calculate(v)
        assert score == 0.0

    # --- VULN_CVSS_MAP ---

    def test_vuln_cvss_map_has_sqli(self):
        assert "sqli" in VULN_CVSS_MAP
        v = VULN_CVSS_MAP["sqli"]
        assert isinstance(v, CVSSVector)

    def test_vuln_cvss_map_scores_are_valid(self):
        for rule_id, vector in VULN_CVSS_MAP.items():
            score = vector.calculate_score()
            assert 0.0 <= score <= 10.0, f"Score for {rule_id} out of range: {score}"
