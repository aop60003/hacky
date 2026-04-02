"""CVSS v3.1 base score calculator."""

from __future__ import annotations

import math
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Metric weights per CVSS v3.1 specification
# ---------------------------------------------------------------------------

_AV_WEIGHT = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC_WEIGHT = {"L": 0.77, "H": 0.44}
_PR_WEIGHT_U = {"N": 0.85, "L": 0.62, "H": 0.27}   # Scope Unchanged
_PR_WEIGHT_C = {"N": 0.85, "L": 0.68, "H": 0.50}   # Scope Changed
_UI_WEIGHT = {"N": 0.85, "R": 0.62}
_CIA_WEIGHT = {"N": 0.00, "L": 0.22, "H": 0.56}


def _roundup(value: float) -> float:
    """CVSS v3.1 Roundup function: rounds to one decimal place, up only."""
    int_input = round(value * 100_000)
    if int_input % 10_000 == 0:
        return int_input / 100_000
    return math.floor(int_input / 10_000 + 1) / 10


@dataclass
class CVSSVector:
    """CVSS v3.1 base metric vector."""

    attack_vector: str = "N"        # N=Network, A=Adjacent, L=Local, P=Physical
    attack_complexity: str = "L"    # L=Low, H=High
    privileges_required: str = "N"  # N=None, L=Low, H=High
    user_interaction: str = "N"     # N=None, R=Required
    scope: str = "U"               # U=Unchanged, C=Changed
    confidentiality: str = "N"      # N=None, L=Low, H=High
    integrity: str = "N"           # N=None, L=Low, H=High
    availability: str = "N"        # N=None, L=Low, H=High

    def calculate_score(self) -> float:
        """Calculate CVSS v3.1 base score."""
        # Impact sub-score
        isc_base = 1 - (
            (1 - _CIA_WEIGHT[self.confidentiality])
            * (1 - _CIA_WEIGHT[self.integrity])
            * (1 - _CIA_WEIGHT[self.availability])
        )

        if self.scope == "U":
            impact = 6.42 * isc_base
        else:
            impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15

        # If no impact, score is 0
        if impact <= 0:
            return 0.0

        # Exploitability sub-score
        pr_weight = (
            _PR_WEIGHT_C[self.privileges_required]
            if self.scope == "C"
            else _PR_WEIGHT_U[self.privileges_required]
        )
        exploitability = (
            8.22
            * _AV_WEIGHT[self.attack_vector]
            * _AC_WEIGHT[self.attack_complexity]
            * pr_weight
            * _UI_WEIGHT[self.user_interaction]
        )

        # Base score
        if self.scope == "U":
            raw = min(impact + exploitability, 10)
        else:
            raw = min(1.08 * (impact + exploitability), 10)

        return _roundup(raw)

    def to_vector_string(self) -> str:
        """Return CVSS v3.1 vector string."""
        return (
            f"CVSS:3.1/AV:{self.attack_vector}/AC:{self.attack_complexity}"
            f"/PR:{self.privileges_required}/UI:{self.user_interaction}"
            f"/S:{self.scope}/C:{self.confidentiality}"
            f"/I:{self.integrity}/A:{self.availability}"
        )


# ---------------------------------------------------------------------------
# Pre-defined vectors for common vulnerability types
# ---------------------------------------------------------------------------

VULN_CVSS_MAP: dict[str, CVSSVector] = {
    # SQL Injection — Network, Low Complexity, No Auth, High CIA → 9.8
    "sqli": CVSSVector(
        attack_vector="N", attack_complexity="L",
        privileges_required="N", user_interaction="N",
        scope="U",
        confidentiality="H", integrity="H", availability="H",
    ),
    # XSS (reflected) — Network, Low, None, Required, Changed, Low CIA → 6.1
    "xss": CVSSVector(
        attack_vector="N", attack_complexity="L",
        privileges_required="N", user_interaction="R",
        scope="C",
        confidentiality="L", integrity="L", availability="N",
    ),
    # SSRF — Network, Low, None, None, Unchanged, High C → 7.5
    "ssrf": CVSSVector(
        attack_vector="N", attack_complexity="L",
        privileges_required="N", user_interaction="N",
        scope="U",
        confidentiality="H", integrity="N", availability="N",
    ),
    # Command Injection — Network, Low, None, None, Unchanged, High CIA → 9.8
    "cmdi": CVSSVector(
        attack_vector="N", attack_complexity="L",
        privileges_required="N", user_interaction="N",
        scope="U",
        confidentiality="H", integrity="H", availability="H",
    ),
    # Path Traversal — Network, Low, None, None, Unchanged, High C, Low I → 8.2
    "path_traversal": CVSSVector(
        attack_vector="N", attack_complexity="L",
        privileges_required="N", user_interaction="N",
        scope="U",
        confidentiality="H", integrity="L", availability="N",
    ),
    # XXE — Network, Low, None, None, Unchanged, High CIA → 9.8
    "xxe": CVSSVector(
        attack_vector="N", attack_complexity="L",
        privileges_required="N", user_interaction="N",
        scope="U",
        confidentiality="H", integrity="H", availability="H",
    ),
    # IDOR — Network, Low, Low, None, Unchanged, High C, Low I → 8.1
    "idor": CVSSVector(
        attack_vector="N", attack_complexity="L",
        privileges_required="L", user_interaction="N",
        scope="U",
        confidentiality="H", integrity="H", availability="N",
    ),
    # Hardcoded Secret — Network, Low, None, None, Unchanged, High C → 7.5
    "hardcoded_secret": CVSSVector(
        attack_vector="N", attack_complexity="L",
        privileges_required="N", user_interaction="N",
        scope="U",
        confidentiality="H", integrity="N", availability="N",
    ),
    # Open Redirect — Network, Low, None, Required, Unchanged, None, Low I → 4.3
    "open_redirect": CVSSVector(
        attack_vector="N", attack_complexity="L",
        privileges_required="N", user_interaction="R",
        scope="U",
        confidentiality="N", integrity="L", availability="N",
    ),
    # CSRF — Network, Low, None, Required, Unchanged, None, Low I, None A → 4.3
    "csrf": CVSSVector(
        attack_vector="N", attack_complexity="L",
        privileges_required="N", user_interaction="R",
        scope="U",
        confidentiality="N", integrity="L", availability="N",
    ),
    # JWT None Algorithm — Network, Low, None, None, Unchanged, High CIA → 9.8
    "jwt_none_alg": CVSSVector(
        attack_vector="N", attack_complexity="L",
        privileges_required="N", user_interaction="N",
        scope="U",
        confidentiality="H", integrity="H", availability="H",
    ),
}


class CVSSCalculator:
    """High-level interface for CVSS score lookup and calculation."""

    def score_for_rule(self, rule_id: str) -> float | None:
        """Return the pre-defined CVSS base score for a known rule_id, or None."""
        vector = VULN_CVSS_MAP.get(rule_id)
        if vector is None:
            return None
        return vector.calculate_score()

    def vector_for_rule(self, rule_id: str) -> CVSSVector | None:
        """Return the pre-defined CVSSVector for a known rule_id, or None."""
        return VULN_CVSS_MAP.get(rule_id)

    def calculate(self, vector: CVSSVector) -> float:
        """Calculate CVSS base score for an arbitrary CVSSVector."""
        return vector.calculate_score()

    def supported_rules(self) -> list[str]:
        """Return list of rule_ids that have pre-defined CVSS vectors."""
        return list(VULN_CVSS_MAP.keys())
