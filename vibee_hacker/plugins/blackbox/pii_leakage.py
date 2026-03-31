# vibee_hacker/plugins/blackbox/pii_leakage.py
"""PII leakage detection plugin."""

from __future__ import annotations

import json
import re
import shlex

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

# PII patterns
PII_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "email",
        re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
        "pii_email",
    ),
    (
        "international_phone",
        re.compile(r"\+\d{1,3}[-\s]\d{3,4}[-\s]\d{3,4}[-\s]\d{4,}\b"),
        "pii_phone_intl",
    ),
    (
        "korean_phone",
        re.compile(r"\b01[016789]-\d{3,4}-\d{4}\b"),
        "pii_phone_kr",
    ),
    (
        "credit_card",
        re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"),
        "pii_credit_card",
    ),
]


def _extract_json_string_values(obj: object, depth: int = 0) -> list[str]:
    """Recursively extract all string values from a JSON object."""
    if depth > 10:
        return []
    values: list[str] = []
    if isinstance(obj, dict):
        for v in obj.values():
            values.extend(_extract_json_string_values(v, depth + 1))
    elif isinstance(obj, list):
        for item in obj[:50]:
            values.extend(_extract_json_string_values(item, depth + 1))
    elif isinstance(obj, str):
        values.append(obj)
    return values


class PiiLeakagePlugin(PluginBase):
    name = "pii_leakage"
    description = "Detect unmasked PII (email, phone, credit card) in JSON API responses"
    category = "blackbox"
    phase = 2
    base_severity = Severity.HIGH
    detection_criteria = "JSON response contains unmasked PII patterns (email, phone, credit card)"
    expected_evidence = "PII pattern match in string values of JSON response body"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        results: list[Result] = []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            try:
                resp = await client.get(target.url)
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return []

            if resp.status_code not in range(200, 300):
                return []

            content_type = resp.headers.get("content-type", "")
            if "application/json" not in content_type:
                return []

            if len(resp.text) > 1_000_000:
                return []

            try:
                data = resp.json()
            except Exception:
                return []

            # Extract all string values from the JSON structure
            string_values = _extract_json_string_values(data)
            combined_text = "\n".join(string_values)

            for pii_type, pattern, rule_id in PII_PATTERNS:
                match = pattern.search(combined_text)
                if match:
                    # Mask the found value for evidence
                    found_value = match.group(0)
                    masked = found_value[:4] + "*" * max(0, len(found_value) - 8) + found_value[-4:] if len(found_value) > 8 else "***"
                    results.append(Result(
                        plugin_name=self.name,
                        base_severity=self.base_severity,
                        title=f"PII leakage: {pii_type} found in API response",
                        description=(
                            f"The API endpoint {target.url} returns JSON containing an unmasked "
                            f"{pii_type} value. Exposing PII in API responses violates privacy "
                            f"regulations (GDPR, CCPA) and increases data breach risk."
                        ),
                        evidence=f"Found {pii_type} pattern in JSON response (sample: {masked})",
                        recommendation=(
                            f"Mask or remove {pii_type} values from API responses. "
                            f"Return only necessary data and apply field-level access control."
                        ),
                        cwe_id="CWE-359",
                        endpoint=target.url,
                        curl_command=f"curl -s {shlex.quote(target.url)}",
                        rule_id=rule_id,
                    ))
                    break  # Report first PII type found, then stop

        return results
